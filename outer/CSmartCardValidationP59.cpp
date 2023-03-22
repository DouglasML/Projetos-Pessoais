#include "CSmartCardValidationP59.h"
#include "CMCA.h"
#include "CContext.h"
#include "CCard.h"
#include "CDevice.h"
#include "CMCAHelper.h"
#include "CFirmwareUtil.h"
#include "CAuthorizedCardList.h"
#include "COutputSocket.h"
#include "CHolidayList.h"
#include "CEventException.h"
#include "CSocketException.h"
#include "CStateTable.h"
#include "CBiometricManager.h"
#include "CValidationException.h"
#include "CPerson.h"
#include "CPersonManager.h"
#include <unistd.h>
#include "CUserCodes.h"
#include "CActionManager.h"
#include "CPasswordManager.h"
#include "CSmartCardUpdates.h"
#include "CCardReader.h"
#include "CBiometricManager.h"
#include "CProcessSmartCard.h"
#include "CSmartCardValidation.h"
#include "dlog.h"

// TODO: eliminar a necessidade desta constante para acessar o bloco de
// pendencias.
#define REQUEST_ACCESS_BLOCK_SIZE 12

namespace seguranca
{

// Tipos de pessoa para Portaria 59
enum EP59PersonType {
    P59PT_Unknown = 0,
    P59PT_Pessoal = 1,
    P59PT_Funcional = 2,
    P59PT_Laboral = 3,
    P59PT_Servico = 4,
    P59PT_Visitante = 5,
};

CSmartCardValidationP59::CSmartCardValidationP59()
    : m_pContext(NULL),             //
      m_Now(0),                     //
      m_eReader(NO_CNFG_READER),    //
      m_nKeyPressed(255),           //
      m_CardType(0),                //
      m_CardTechnology(0),          //
      m_iPendenceBufferSize(0),     //
      fIsValidAccess(false),        //
      fUseBigEndian(false),         //
      fIsDocumentValidation(false), //
      fDocument(0LL)                //
{
}

CSmartCardValidationP59::~CSmartCardValidationP59() {}

void CSmartCardValidationP59::Reset(const CCard Card, EReader eReader, BYTE nKeyPressed,
                                    CContext *pContext)
{
    m_Card = Card;
    m_eReader = eReader;
    m_nKeyPressed = nKeyPressed;
    m_pContext = pContext;

    m_Buffer.Clear();
    m_Buffer.SetLimit(0);
    m_iPendenceBufferSize = 0;
    m_CardType = CReaderConfig::NONE;
    m_CardTechnology = CCard::CT_Unknown;
    fDocument = 0LL;

    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    m_Now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, m_pContext->GetConfiguration()->GetProperties());

    fIsDocumentValidation =
        m_pContext->GetConfiguration()->GetSmartCardValidationType() ==
        SMART_PORTARIA59_DOCUMENT;
    fIsValidAccess = true;
}

CValidationResult CSmartCardValidationP59::ValidateCard(const CCard Card, EReader eReader,
                                                        BYTE nKeyPressed,
                                                        CContext *pContext)
{
    Reset(Card, eReader, nKeyPressed, pContext);

    CheckSmartCardMapConfigured();

    CValidationResult valRes;

    valRes.GetEvent().SetCard(m_Card);

    // Limpa os buffers e associa um novo identificador (Aqui? Definir...)
    PrepareSmartCard(&fSmartCardHandler);

    // Valida o acesso no sistema
    CheckSystemValidation(valRes);

    if (fIsValidAccess) {
        // Valida regras da portaria 59
        CheckPortaria59(valRes);
    }

    return valRes;
}

void CSmartCardValidationP59::CheckSystemValidation(CValidationResult &valRes)
{
    // Online e sem estar no modo "Quiet"?
    if (m_pContext->GetOutputSocket()->HasCSMComm() &&
        !m_pContext->GetOutputSocket()->IsQuietMode()) {
        // Faz a requisição de validação
        RequestValidation();

        if (m_Buffer.Limit() > 0) {
            try {
                // Analisa o resultado da validacao
                ParseValidationData(valRes);

            } catch (CValidationException &ex) {
                ex.Raise();
            } catch (CEventException &ex) {
                valRes.SetEvent(ex.GetEvent());
                valRes.GetEvent().SetReader(m_eReader);
                fIsValidAccess = false;
            }
        }
    }

    // tipo da pessoa
    valRes.SetCardType(m_CardType);

    if (fIsValidAccess) {
        try {
            bool bOnline = !m_pContext->GetOutputSocket()->IsQuietMode() &&
                           m_pContext->GetOutputSocket()->HasCSMComm();

            ValidacaoPadrao(bOnline, valRes);

        } catch (CValidationException &ex) {
            ex.Raise();
        } catch (CEventException &ex) {
            valRes.SetEvent(ex.GetEvent());
            fIsValidAccess = false;
        }
    }

    valRes.GetEvent().SetReader(m_eReader);

    // É validação por documento?
    if (fIsDocumentValidation) {
        DLOG_INFO("Pessoa:    \"%s\"\n", valRes.GetPersonId());
        DLOG_INFO("Matricula: \"%lld\"\n", valRes.GetEnroll().GetId());
        DLOG_INFO("Documento: \"%lld\"\n", fDocument);

        valRes.GetEvent().SetDocumentId(fDocument, m_Card);

        if (strlen(valRes.GetPersonId()) == 0) {
            if (fIsValidAccess) {
                // Entrando aqui, e provavel que esteja offline.
                // Se as condicoes levaram ao acesso permitido ate aqui,
                // bloqueia o acesso porque nao sabemos se existe o cadastro
                // do documento no sistema.
                DLOG_INFO("PESSOA NAO IDENTIFICADA, ACESSO BLOQUEADO!\n");
                valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_SITUATION);
                fIsValidAccess = false;
            }
        }
    }

    // define qual sera o nivel
    if (fIsValidAccess &&
        !m_pContext->GetConfiguration()->GetFunctionIgnoreLevel(m_nKeyPressed)) {
        valRes.SetNewLevel(CalcNextLevel(valRes.GetOriginalLevel()));
        valRes.GetEvent().SetLevel(valRes.GetNewLevel());
    } else {
        valRes.SetNewLevel(valRes.GetOriginalLevel());
    }
}

void CSmartCardValidationP59::ValidacaoPadrao(bool bOnLineValidation,
                                              CValidationResult &valRes)
{
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);

    if (strlen(valRes.GetPersonId()) == 0) {
        // tenta encontrar a pessoa ligada ao cartao
        CPerson person;
        if (m_pContext->GetPersonManager()->FindPersonByCard(m_Card, person)) {
            valRes.SetPersonId(person.GetId());
            valRes.SetConferenceLevel(person.GetConferenceLevel());
        }
    }

    // Byte para verificar qual é o tipo do cartao da lista
    BYTE CardType = CReaderConfig::NONE;

    // validacao pela lista
    if (pReaderConfig->CheckList() || !bOnLineValidation) {
        if (!m_pContext->GetAuthorizedCardList()->Contains(m_Card, m_eReader, CardType)) {
            // MMF - Include Reader for those events 10/02/2016
            valRes.GetEvent().SetReader(m_eReader);
            if (m_pContext->GetAuthorizedCardList()->CardListType() ==
                CAuthorizedCardList::authorizedList) {
                throw CEventException(CEvent::ACCESS_DENIED_WHITE_LIST, m_Card);
            } else {
                throw CEventException(CEvent::ACCESS_DENIED_BLACK_LIST, m_Card);
            }
        }
    }

    if (!bOnLineValidation) {
        // Se a validação não foi online, pega o tipo do cartão que veio da
        // lista de liberação.
        m_CardType = CardType;

        // revista aleatória
        if (pReaderConfig->CheckFriskRanges(m_Now)) {
            BYTE friskPercent = pReaderConfig->GetFriskPercent(m_CardType - 1);
            if (friskPercent) {
                valRes.SetFrisk(FRISK_RANDOM);
            }
        }

        CFirmwareProperties *pFirmProps =
            &m_pContext->GetConfiguration()->GetProperties();
        // Verifica se a leitora nao controla ambos os sentidos
        if (!pFirmProps->IsReaderBothDirections(m_eReader)) {
            // verifica se a leitora é do tipo saida
            if (CAccessEvent::AD_Out == pFirmProps->GetAccessDirection(m_eReader, true)) {
                if (GET_PERSON_TYPE(CardType) != CReaderConfig::NONE) {
                    BYTE BlockType = pReaderConfig->GetPersonsAllowOut();
                    // verifica se o tipo do cartao esta bloqueado na saida
                    if (((BlockType >> (CardType - 1)) & 1) == 0) {
                        DLOG_INFO("Cartao bloqueado na saida\n");
                        throw CEventException(CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT,
                                              m_Card);
                    }
                }
            }
        }

        // caso nao seja um acesso negado, verifica se foi uma validacao do
        // cartao mestre
        if (GET_PERSON_TYPE(CardType) == CReaderConfig::MASTER_CARD) {
            // cartão mestre nao valida biometria
            valRes.SetConferenceLevel(0);
            // ser for um cartao mestre, e nao estiver bloqueado na saida, entao
            // envento = cartao mestre
            if (valRes.GetEvent().GetId() != CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT)
                valRes.GetEvent().SetId(CEvent::ACCESS_MASTER_CARD);
        }

        // Lista de senhas
        if (pReaderConfig->CheckPassword()) {
            const BYTE *password = m_pContext->GetUserCodes()->HasPassword(m_Card);
            // seta a senha se a mesma é válida
            if (password != NULL) {
                valRes.SetPassword(password);
            }
        }
        // Se chegou aqui o acesso permitido.
        valRes.GetEvent().SetId(CEvent::ACCESS_GRANTED);
    }
}

void CSmartCardValidationP59::RequestValidation()
{
    CBuffer requestBuffer;
    // recolhe os dados necessarios na validacao
    DLOG_INFO("Preparando dados...\n");
    PrepareData(requestBuffer);
    // faz o pedido de validacao ao driver
    if (m_pContext->GetConfiguration()->GetSmartCardValidationType() ==
        SMART_PORTARIA59_DOCUMENT) { //É validação por documento?
        m_pContext->GetOutputSocket()->RequestSizedData(RequestDocumentValidation,
                                                        requestBuffer, m_Buffer);
    } else { //É validação por ID de cartão...
        m_pContext->GetOutputSocket()->RequestSizedData(RequestCardValidation,
                                                        requestBuffer, m_Buffer);
    }
}

void CSmartCardValidationP59::PrepareData(CBuffer &dest)
{

    // Verifica se é validação por documento armazenado no mapa do cartão:
    if (fIsDocumentValidation) {
        dest.PutByte((BYTE)DT_Unrecognized); // Tipo do documento (Desconhecido)...
        dest.PutWord((BYTE)(5 + 5));         // Tamanho do documento
        dest.PutCardId(m_Card.GetId());
        DLOG_INFO("Phisical Number: %lld\n", m_Card.GetId());
        dest.PutCardId(fDocument);

    } else { // Se não é validação por documento, é validação normal com
             // identificador... (SMART_PORTARIA59_ID)
        // identificador
        m_Card.GetInternalData(dest);
    }

    // data e hora local
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    UINT now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, m_pContext->GetConfiguration()->GetProperties());
    dest.PutUInt(now);
    // Data do último acesso
    dest.PutUInt(0);
    // Nível atual do cartão
    dest.PutByte(0);
    // leitora
    dest.PutByte(m_eReader + 1);
    // identifica se eh feriado
    dest.PutByte(
        m_pContext->GetHolidayList()->Contains(CFirmwareUtil::GetDateInDays(now)));
    // informa a funcao
    dest.PutByte(m_nKeyPressed);
    dest.Flip();
}

void CSmartCardValidationP59::ParseValidationData(CValidationResult &valRes)
{

    // campo: "Ignorar resposta sobre permissão de acesso e validar pela lista?
    // 0 - não, 1 - sim";
    // Não usado neste escopo! Apenas passa...
    m_Buffer.GetByte();

    // tipo de retorno
    const EValReturnType eReturnType = (EValReturnType)m_Buffer.GetByte();

    // retornou mensagem ?
    if (eReturnType == VR_Message) {
        DLOG_INFO("PESSOA NAO ENCONTRADA NO DATAMART\n\n");
        BYTE nMessageId = m_Buffer.GetByte();
        char ReturnMsgLine1[16];
        m_Buffer.GetBytes(ReturnMsgLine1, 16);
        char ReturnMsgLine2[16];
        m_Buffer.GetBytes(ReturnMsgLine2, 16);
        CDisplay::DisplayText Message;
        memset(&Message, 0, sizeof(Message));
        memcpy(Message.line1, ReturnMsgLine1, 16);
        memcpy(Message.line2, ReturnMsgLine2, 16);
        throw CValidationException(nMessageId, Message);
    } else if (eReturnType == VR_Card) {
        // Não utiliza pois aqui só entra cartões de barras e RFID
        m_iPendenceBufferSize = m_Buffer.GetUInt();

        char personId[PERSONID_SIZE + 1];
        m_Buffer.GetBytes(personId, PERSONID_SIZE);
        personId[PERSONID_SIZE] = 0;
        DLOG_INFO("Person: %s\n", personId);
        valRes.SetPersonId((char *)personId);
    }

    // identificador do evento
    const CEvent::EventCode eventId = (CEvent::EventCode)m_Buffer.GetByte();
    valRes.GetEvent().SetId(eventId);
    // persiste para comparação futura, se houver alteração do ID durante o
    // curso da validação...
    valRes.SetOriginalEventFromCSM(eventId);
    valRes.GetEvent().SetReader(m_eReader);

    // numero de matricula do cartao
    CCard enroll;
    enroll.ParseId(m_Buffer);
    valRes.SetEnroll(enroll);

    // Tipo do cartão
    m_CardType = m_Buffer.GetByte();
    // tecnologia do cartao
    m_CardTechnology = m_Buffer.GetByte();

    // mensagem do colaborador
    // usada somente sem funcao
    BYTE CollabMsg[32];
    m_Buffer.GetBytes(CollabMsg, 32);
    if (m_nKeyPressed == 255) {
        char szCollabMsg[33];
        char szEmpty[33];
        szCollabMsg[32] = 0;
        memcpy(szCollabMsg, CollabMsg, 32);
        memset(szEmpty, 0, sizeof(szEmpty));

        if (memcmp(szCollabMsg, szEmpty, 33) != 0) {
            valRes.SetCollaboratorMsg(szCollabMsg);
            valRes.GetEvent().SetMessageUsedFlag(true);
        }
    }

    BYTE bLevel = 0;
    BYTE temp[12];
    UINT beforeEventData = m_Buffer.Position();

    try {
        // identifica se eh um acesso valido
        switch (eventId) {
        case 0:
            DLOG_INFO("Retorno de evento zero, trocando por Negado Lista\n");
            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_WHITE_LIST);
        // no break
        default:
            bLevel = m_Buffer.GetByte();
            valRes.SetOriginalLevel((eventId == 0) ? EMPTY_LEVEL : bLevel);
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_INTERJOURNEY:
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_LUNCH_INTERVAL:
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_FAULT:
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
            break;
        case CEvent::ACCESS_DENIED_VALIDITY: {
            UINT pExpirationDate = m_Buffer.GetUInt(); // Validade do cartao
            valRes.GetEvent().SetValidity(pExpirationDate);
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 7);
            throw CEventException(valRes.GetEvent());
        }
        case CEvent::ACCESS_DENIED_LEVEL:
        case CEvent::ACCESS_DENIED_ANTIPASSBACK:
            valRes.GetEvent().SetFlowType(m_Buffer.GetByte());
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            valRes.GetEvent().SetLevel(valRes.GetOriginalLevel());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 10);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_REMOVAL: {
            UINT start = m_Buffer.GetUInt();
            UINT end = m_Buffer.GetUInt();
            valRes.GetEvent().SetRemovalPeriod(start, end);
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 3);
            throw CEventException(valRes.GetEvent());
        }
        case CEvent::ACCESS_DENIED_PASSWORD:
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_MIN_TIME:
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            // Apenas passa os bytes não utilizados
            m_Buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_GRANTED:
        case CEvent::ACCESS_GRANTED_COERCION:
        case CEvent::ACCESS_MASTER_CARD:
        case CEvent::ACCESS_GRANTED_OUT_REPOSE:
        case CEvent::ACCESS_GRANTED_CHEAT:
        case CEvent::ACCESS_DENIED_WAITING_FOR_NEXT_VALIDATION:
        case CEvent::ACCESS_VALID_AUTHORIZER:
        case CEvent::ACCESS_DENIED_WAITING_CONDUCTOR:
        case CEvent::ACCESS_DENIED_WAITING_VEHICLE:
        case CEvent::ACCESS_GRANTED_CONDUCTOR:
        case CEvent::ACCESS_DENIED_CROWDED: {
            valRes.SetOriginalLevel(m_Buffer.GetByte());
            valRes.GetEvent().SetAccessCredits(m_Buffer.GetByte());
            valRes.SetConferenceLevel(m_Buffer.GetByte());
            valRes.SetFrisk(m_Buffer.GetByte());
            DLOG_INFO("\nRETORNO DO SERVIDOR (VALIDACAO)\n" //
                      "Level: %d\n"
                      "AccessCreditRange: %d\n"
                      "ConferenceLevel: %d (%s)\n"
                      "Revista: %d\n\n",                    //
                      valRes.GetOriginalLevel(),            //
                      valRes.GetEvent().GetAccessCredits(), //
                      valRes.GetConferenceLevel(),          //
                      valRes.CardCheckBiometry() ? "VALIDA BIOMETRIA"
                                                 : "NAO VALIDA BIOMETRIA", //
                      valRes.GetFrisk());

            // se a senha é válida seta que a pessoa usa senha
            BYTE Password[6];
            m_Buffer.GetBytes(Password, 6);
            valRes.SetPassword(Password);
            m_Buffer.GetByte(); // Flags
            m_Buffer.GetByte(); // CreditControlType

        } break;
        }
    } catch (CEventException &ex) {
        m_Buffer.SetPosition(beforeEventData + REQUEST_ACCESS_BLOCK_SIZE);
        ex.Raise();
    }
}

void CSmartCardValidationP59::CheckSmartCardMapConfigured()
{
    // Verifica se existe mapa do smartcard
    if (m_pContext->GetConfiguration()->GetSmartCardMap().IsEmpty()) {
        if (m_pContext->GetConfiguration()->GetReaderConfig(m_eReader).UseDisplay()) {
            CAction action;
            action.GetDisplay().SetAction(1);
            action.GetDisplay().SetTime(2000);
            CDisplay::DisplayText theText;
            memcpy(theText.line1, "    CARREGAR    ", 16);
            memcpy(theText.line2, " MAPA DO CARTAO ", 16);
            action.SetDisplayMsg(&theText);
            m_pContext->GetActionManager()->QueueActions(action);
        }
        throw CException("smart card map is empty");
    }
}

void CSmartCardValidationP59::CheckPendencies(CSmartCardHandlerBase *pSmartCardHandler)
{
    if (m_iPendenceBufferSize > 0) {
        DLOG_INFO("SmartCard possui pendencias\n");

        if ((size_t)m_iPendenceBufferSize != (m_Buffer.Limit() - m_Buffer.Position())) {
            // verifique se REQUEST_ACCESS_BLOCK_SIZE está coerente com o
            // datagrama.
            DLOG_ERROR("### ERRO\n");
            throw CException("Problemas no retorno de requisicao de acesso");
        }

        DLOG_INFO("Pendencias ignoradas quando portaria 59\n");
    } else {
        DLOG_INFO("SmartCard sem pendencias\n");
    }
}

bool CSmartCardValidationP59::IsEntrance(BYTE Level)
{
    CFirmwareProperties &props = m_pContext->GetConfiguration()->GetProperties();
    const bool bLevelOneToLevelTwo =
        (Level != props.GetReaderLevel2(m_eReader)) || (Level == EMPTY_LEVEL);
    CAccessEvent::AccessDirection ad =
        props.GetAccessDirection(m_eReader, bLevelOneToLevelTwo);
    return (ad == CAccessEvent::AD_In);
}

void CSmartCardValidationP59::CheckEntrance(CValidationResult &valRes)
{
    DLOG_INFO("Efetuando ENTRADA\n");

    UINT EnclosureId = m_pContext->GetConfiguration()->GetEnclosureId();
    DLOG_INFO("Recinto atual: %d\n", EnclosureId);

    CBuffer temp(2);
    temp.SetBigEndian(fUseBigEndian);
    fSmartCardHandler.GetFieldValue(CSmartCardMap::P65_Emissao, temp.Data(),
                                    temp.Limit());
    WORD Emissao = temp.GetWord();

    // Data de emissao vem em segundos desde 1/1/2000, então converte para
    // timestamp do C
    time_t EmissionDate = CFirmwareUtil::ConvertToTimestamp(Emissao);

    temp.Clear();
    fSmartCardHandler.GetFieldValue(CSmartCardMap::P65_Validade, temp.Data(), 2);
    WORD ValidDays = temp.GetWord();

    // Calcula a validade
    time_t Validity = (EmissionDate + ValidDays) * SECONDS_PER_DAY;
    if (Validity < 0) {
        // Excedeu o limite da data no C para 32 bits, então usa o máximo
        // disponível
        Validity = INT_MAX;
    }

    { //// DEBUG_BEGIN
        DLOG_INFO("Emissao:  %05d %04X\n", Emissao, Emissao);
        DLOG_INFO("Validade: %05d %04X\n", ValidDays, ValidDays);

        char szValidity[STRDATETIMELEN];
        CFirmwareUtil::GetDateTimeString(EmissionDate * SECONDS_PER_DAY, szValidity,
                                         STRDATETIMELEN);
        DLOG_INFO("Emissao calculada: %lu (%s)\n", EmissionDate, szValidity);
        DLOG_INFO("Calculado: %lu\n", Validity);

        CFirmwareUtil::GetDateTimeString(Validity, szValidity, STRDATETIMELEN);
        DLOG_INFO("Validade do cartao: %s\n", szValidity);
    } //// DEBUG_END

    // Verifica se ainda está dentro do prazo
    if (Validity < m_Now) {
        char szValidity[STRDATETIMELEN];
        CFirmwareUtil::GetDateTimeString(Validity, szValidity, STRDATETIMELEN);
        DLOG_INFO("Acesso negado pela validade: %s\n", szValidity);
        valRes.GetEvent().SetId(CAccessEvent::ACCESS_DENIED_VALIDITY);
        valRes.GetEvent().SetValidity(Validity);
        throw CEventException(valRes.GetEvent());
    }
}

void CSmartCardValidationP59::CheckExit(CValidationResult &valRes)
{
    DLOG_INFO("Efetuando SAIDA\n");

    UINT EnclosureId = m_pContext->GetConfiguration()->GetEnclosureId();
    DLOG_INFO("Recinto atual: %d\n", EnclosureId);

    return; // Acesso permitido
}

void CSmartCardValidationP59::CheckPortaria59(CValidationResult &valRes)
{

    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);

    try {

        CheckPendencies(&fSmartCardHandler);

        if (IsEntrance(valRes.GetOriginalLevel())) {
            CheckEntrance(valRes);
        } else {
            CheckExit(valRes);
        }
    } catch (CEventException &ex) {
        DLOG_INFO("Acesso Negado: %s\n", ex.GetMessage());
        fIsValidAccess = false;
        valRes.SetEvent(ex.GetEvent());

    } catch (CValidationException &ex) {
        ex.Raise();

    } catch (CDispositiveException &ex) {
        if (pReaderConfig->GetValidAccessAction().GetUrn().GetAction() == 1) {
            CAction UrnAction;
            UrnAction.GetUrn().SetTime(1000);
            UrnAction.GetUrn().SetAction(1);
            m_pContext->GetActionManager()->QueueActions(UrnAction);
        }
        if (pReaderConfig->UseDisplay() &&
            !m_pContext->GetActionManager()->IsUsingDisplay()) {
            CMCAHelper::TimedDisplay(1000, "Erro na leitura ", "                ",
                                     m_pContext);
        }
        ex.Raise();

    } catch (CException &ex) {
        DLOG_ERROR("Erro generico na validacao do acesso\n");
        if (pReaderConfig->UseDisplay() &&
            !m_pContext->GetActionManager()->IsUsingDisplay()) {
            CMCAHelper::TimedDisplay(1200, "Acesso negado   ", "Erro generico   ",
                                     m_pContext);
        }
        ex.Raise();
    }

    try {
        fSmartCardHandler.SaveModifiedData();
        DLOG_INFO("Salvou as modificacoes no cartao.\n");

    } catch (CException &ex) {
        DLOG_WARNING("Erro na gravacao do cartao: %s\n", ex.GetMessage());
        if (pReaderConfig->UseDisplay() &&
            !m_pContext->GetActionManager()->IsUsingDisplay()) {
            CMCAHelper::TimedDisplay(1000, "Erro na gravacao", "                ",
                                     m_pContext);
        }
        ex.Raise();
    }
}

BYTE CSmartCardValidationP59::CalcNextLevel(BYTE nOriginalLevel)
{
    CFirmwareProperties &props = m_pContext->GetConfiguration()->GetProperties();
    const BYTE readerLevel1 = props.GetReaderLevel1(m_eReader);
    const BYTE readerLevel2 = props.GetReaderLevel2(m_eReader);
    DLOG_INFO("ReaderLevel(%d, %d) - CardLevel(%d)\n", readerLevel1, readerLevel2,
              nOriginalLevel);

    if (nOriginalLevel == EMPTY_LEVEL || nOriginalLevel == readerLevel1) {
        return readerLevel2;
    } else if (nOriginalLevel == readerLevel2) {
        if (props.IsReaderBothDirections(m_eReader)) {
            return readerLevel1;
        } else {
            return readerLevel2;
        }
    }
    DLOG_WARNING("NIVEL NO SERVIDOR (%d) DIFERE DO CONFIGURADO NO DISPOSITIVO (N1:%d, "
                 "N2:%d)\n",
                 nOriginalLevel, readerLevel1, readerLevel2);
    return nOriginalLevel;
}

void CSmartCardValidationP59::PrepareSmartCard(CSmartCardHandlerBase *pSmartCardHandler)
{

    CMCA::ECardReader eCardReader = (CMCA::ECardReader)m_eReader;
    CCardReader *pCardReader = m_pContext->GetMCA()->GetCardReader(eCardReader);

    fSmartCardHandler.Reset(m_Card, &m_pContext->GetConfiguration()->GetSmartCardMap(),
                            (CSmartCardReader *)pCardReader);
    fSmartCardHandler.SetCanFormat(true);

    if (fIsDocumentValidation) {
        // Carrega o documento
        const int fieldSize = 5;
        CBuffer CpfField(fieldSize);
        CpfField.SetBigEndian(fUseBigEndian);
        if (fSmartCardHandler.GetFieldValue(CSmartCardMap::P65_CPF, CpfField.Data(),
                                            CpfField.Limit()) == fieldSize) {
            fDocument = CpfField.GetCardId();
        } else {
            // Tamanho campo diferente tamanho informado para tipo!!!
            throw CException::Format("Campo de documento requerido no "
                                     "smartcard esta diferente do tamanho "
                                     "informado!");
        }
    }
}
}

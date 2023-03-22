#include "CSmartCardLogicalIDValidation.h"
#include "CMCA.h"
#include "CContext.h"
#include "CCard.h"
#include "CDevice.h"
#include "CMCAHelper.h"
#include "CFirmwareUtil.h"
#include "CAuthorizedCardList.h"
#include "CHolidayList.h"
#include "COutputSocket.h"
#include "CEventException.h"
#include "CSocketException.h"
#include "CValidationException.h"
#include "CPersonManager.h"
#include "CUserCodes.h"
#include <unistd.h>
#include "CActionManager.h"
#include "CSmartCardHandler.h"
#include "CCardReader.h"
#include "CProcessSmartCard.h"
#include "CSmartCardValidation.h"

using digicon::CMCA;
using digicon::CCard;
using digicon::CCardReader;
using seguranca::CMCAHelper;
using digicon::CValidationException;
using base::CSocketException;

#define CPF_SIZE 5
#define PASSPORT_SIZE 5
#define RENAVAM_SIZE 5
#define LOGICAL_SIZE 5
#define LOGICAL_SIZE_TELEMATICA 6

namespace seguranca
{

CSmartCardLogicalIDValidation::CSmartCardLogicalIDValidation()
    : m_pContext(NULL), m_pSmartCardHandler(NULL), m_eReader(NO_CNFG_READER),
      m_nKeyPressed(255), m_CardType(0), m_CardTechnology(0), m_SizeOfFields(0),
      m_LogicalNumber(0LL), m_Now(0), m_bPersonValidation(false), fUseBigEndian(false),
      fOnlineCheckList(false)
{
    m_pSmartCardHandler = new CSmartCardHandler();
    memset(m_FieldInUse, 0, sizeof(m_FieldInUse));
}

CSmartCardLogicalIDValidation::~CSmartCardLogicalIDValidation()
{
    SAFE_DELETE(m_pSmartCardHandler);
}

CValidationResult CSmartCardLogicalIDValidation::ValidateCard(const CCard Card,
                                                              EReader eReader,
                                                              BYTE nKeyPressed,
                                                              CContext *pContext)
{

    m_Buffer.Clear();
    m_pContext = pContext;
    m_eReader = eReader;

    m_CardType = CReaderConfig::NONE;
    m_CardTechnology = CCard::CT_Unknown;
    m_nKeyPressed = nKeyPressed;
    m_Card = Card;
    m_bPersonValidation = (Card.GetTecnology() == CCard::CT_Person);

    //----------------------------------------------------
    CAccessEvent ae;
    ae.SetId(CEvent::ACCESS_GRANTED);
    ae.SetLevel(EMPTY_LEVEL);
    ae.SetAccessCredits(0xFF);
    ae.SetReader(m_eReader);
    //---------------------------------------------
    CValidationResult valRes;
    valRes.SetEvent(ae);
    // Identifica a entrada da validacao
    if (m_bPersonValidation) {
        valRes.GetEvent().SetPersonId(Card.GetPerson());
        valRes.SetPersonId(Card.GetPerson());
    } else {
        valRes.GetEvent().SetCard(Card);
    }

    bool bValidAccess = true;

    if (m_pContext->IsOnline() && !m_pContext->GetOutputSocket()->IsQuietMode()) {
        // Prepara e requisita o acesso à concentradora...
        internal_ValidateCard();

        if (m_Buffer.Limit() > 0) {
            DLOG_INFO("Tamanho de bloco recebido: %d\n", m_Buffer.Limit());
            try {
                // Analisa o resultado da validacao
                ParseValidationData(valRes, m_Buffer);

            } catch (CValidationException &ex) {
                ex.Raise();
            } catch (CEventException &ex) {
                valRes.SetEvent(ex.GetEvent());
                bValidAccess = false;
            }
        } else {
            DLOG_WARNING("\n\n\nFALHA NO RETORNO DA REQUISICAO DE ACESSO!!!\n");
            DLOG_WARNING("\nValidando apenas pela lista local...\n\n\n");
        }

    } else { // Validação é offline e só consulta a lista...

        // Coleta informações do(s) campo(s) do smart...
        PrepareSmartCard();
    }

    if (bValidAccess) {
        try {

            bool bOnline = m_pContext->GetOutputSocket()->HasCSMComm();
            // Validação Padrão
            DefaultValidation(bOnline, valRes);

        } catch (CValidationException &ex) {
            ex.Raise();
        } catch (CEventException &ex) {
            valRes.SetEvent(ex.GetEvent());
            bValidAccess = false;
        }
    }

    // numero da matricula
    valRes.SetEnroll(m_Card);
    // Seta número lógico + número físico
    valRes.GetEvent().SetLogicalNumber(m_LogicalNumber, m_Card);
    // tipo da pessoa
    valRes.SetCardType(m_CardType);
    // leitora
    valRes.GetEvent().SetReader(m_eReader);

    // Mostra informações...
    DLOG_INFO("Numero Fisico: \"%lld\"\n", m_pSmartCardHandler->GetCard().GetId());
    DLOG_INFO("Numero Logico: \"%lld\"\n", m_LogicalNumber);

    // Define o novo nivel
    if (bValidAccess &&
        !pContext->GetConfiguration()->GetFunctionIgnoreLevel(nKeyPressed)) {
        valRes.SetNewLevel(CalcNextLevel(valRes.GetOriginalLevel()));
        valRes.GetEvent().SetLevel(valRes.GetNewLevel());
    } else {
        valRes.SetNewLevel(valRes.GetOriginalLevel());
    }

    return valRes;
}

void CSmartCardLogicalIDValidation::internal_ValidateCard()
{
    // recolhe os dados necessarios na validacao
    CBuffer ValRequest;
    PrepareData(ValRequest);
    // faz o pedido de validacao ao driver
    m_pContext->GetOutputSocket()->RequestSizedData(RequestDocumentValidation, ValRequest,
                                                    m_Buffer);
}

void CSmartCardLogicalIDValidation::PrepareData(CBuffer &dest)
{

    PrepareSmartCard();

    DLOG_INFO("\nTipo de Validacao na requisicao de acesso: \n");
    DLOG_INFO("Numero Logico\n");

    dest.PutByte((BYTE)DT_Logical_Number); // Tipo do documento (Número Lógico)...

    // TODO: Protocolo 6.9 -> Inserindo 5 bytes do numero físico do cartão
    dest.PutWord((BYTE)(5 + 5));

    // Numero fisico
    dest.PutCardId(m_pSmartCardHandler->GetCard().GetId());
    DLOG_INFO("Physical Number: %llu\n", m_pSmartCardHandler->GetCard().GetId());

    // Insere número lógico
    dest.PutCardId(m_LogicalNumber);
    DLOG_INFO("\nLogical_Number == %llu;\n", m_LogicalNumber);

    // data e hora local
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    UINT now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, m_pContext->GetConfiguration()->GetProperties());
    dest.PutUInt(now);
    // Data do último acesso
    dest.PutUInt((BYTE)0);
    // Nível atual do cartão
    dest.PutByte((BYTE)0);
    // leitora
    dest.PutByte(m_eReader + 1);
    // identifica se eh feriado
    dest.PutByte(
        m_pContext->GetHolidayList()->Contains(CFirmwareUtil::GetDateInDays(now)));
    // informa a funcao
    dest.PutByte(m_nKeyPressed);
    dest.Flip();
}

void CSmartCardLogicalIDValidation::ParseValidationData(CValidationResult &valRes,
                                                        CBuffer &buffer)
{

    // campo: "Ignorar resposta sobre permissão de acesso e validar pela lista?
    // 0 - não, 1 - sim";
    fOnlineCheckList = (buffer.GetByte() == 1) ? true : false;
    // tipo de retorno
    const EValReturnType eReturnType = (EValReturnType)buffer.GetByte();

    // retornou mensagem ?
    if (eReturnType == VR_Message) {
        DLOG_INFO("PESSOA NAO ENCONTRADA NO DATAMART\n\n");
        BYTE nMessageId = buffer.GetByte();
        char ReturnMsgLine1[16];
        buffer.GetBytes(ReturnMsgLine1, 16);
        char ReturnMsgLine2[16];
        buffer.GetBytes(ReturnMsgLine2, 16);
        CDisplay::DisplayText Message;
        memset(&Message, 0, sizeof(Message));
        memcpy(Message.line1, ReturnMsgLine1, 16);
        memcpy(Message.line2, ReturnMsgLine2, 16);
        throw CValidationException(nMessageId, Message);
    } else if (eReturnType == VR_Card) {
        // Não utiliza pois aqui só entra cartões de barras e RFID
        buffer.GetUInt(); // UINT PendenceBufferSize

        char personId[PERSONID_SIZE + 1];
        buffer.GetBytes(personId, PERSONID_SIZE);
        personId[PERSONID_SIZE] = 0;
        DLOG_INFO("Person: %s\n", personId);
        valRes.SetPersonId((char *)personId);
    } else {
        valRes.SetPersonId(m_Card.GetPerson());
    }

    // identificador do evento
    CEvent::EventCode eventId = (CEvent::EventCode)buffer.GetByte();
    valRes.GetEvent().SetId(eventId);
    // persiste para comparação futura, se houver alteração do ID durante o
    // curso da validação...
    valRes.SetOriginalEventFromCSM(eventId);
    valRes.GetEvent().SetReader(m_eReader);

    // Caso a resposta mande validar pela lista, "desconsidera" a resposta da
    // validação usando a resposta padrão!
    if (fOnlineCheckList) {
        eventId = (CEvent::EventCode)CAccessEvent::ACCESS_GRANTED;
        valRes.GetEvent().SetId(eventId);
    }

    if (m_bPersonValidation) {
        m_Card.ParseId(buffer);
        valRes.GetEvent().SetCard(m_Card);
    }

    // numero de matricula do cartao
    CCard enroll;
    enroll.ParseId(buffer);
    valRes.SetEnroll(enroll);

    //	if(!m_bPersonValidation) {
    m_CardType = buffer.GetByte();
    m_CardTechnology = buffer.GetByte();
    //	}

    // mensagem do colaborador
    // usada somente sem funcao
    BYTE CollabMsg[32];
    buffer.GetBytes(CollabMsg, 32);
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

    // identifica se eh um acesso valido
    BYTE bLevel = 0;
    BYTE temp[12];
    switch (eventId) {
    case 0:
        DLOG_INFO("Retorno de evento zero, trocando por Negado Lista\n");
        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_WHITE_LIST);
    // no break
    default:
        bLevel = buffer.GetByte();
        valRes.SetOriginalLevel((eventId == 0) ? EMPTY_LEVEL : bLevel);
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // Acesso negado por interjornada de trabalho
    case CEvent::ACCESS_DENIED_INTERJOURNEY:
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // Acesso negado intervalo de almoco
    case CEvent::ACCESS_DENIED_LUNCH_INTERVAL:
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // acesso negado bloqueio por falta
    case CEvent::ACCESS_DENIED_FAULT:
        valRes.SetOriginalLevel(buffer.GetByte());
        throw CEventException(valRes.GetEvent());
    // acesso negado validade
    case CEvent::ACCESS_DENIED_VALIDITY:
        valRes.GetEvent().SetValidity(buffer.GetUInt()); // Validade do cartao
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 7);
        throw CEventException(valRes.GetEvent());
    // acesso negado nivel
    case CEvent::ACCESS_DENIED_LEVEL:
    case CEvent::ACCESS_DENIED_ANTIPASSBACK:
        valRes.GetEvent().SetFlowType(buffer.GetByte());
        valRes.SetOriginalLevel(buffer.GetByte());
        valRes.GetEvent().SetLevel(valRes.GetOriginalLevel());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 10);
        throw CEventException(valRes.GetEvent());
    // acesso negado afastamento
    case CEvent::ACCESS_DENIED_REMOVAL: {
        UINT start = buffer.GetUInt();
        UINT end = buffer.GetUInt();
        valRes.GetEvent().SetRemovalPeriod(start, end);
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 3);
        throw CEventException(valRes.GetEvent());
    }
    // acesso negado senha
    case CEvent::ACCESS_DENIED_PASSWORD:
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // acesso negado tempo minimo de permanencia
    case CEvent::ACCESS_DENIED_MIN_TIME:
        valRes.SetOriginalLevel(buffer.GetByte());
        // Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // acessos permitidos
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
        valRes.SetOriginalLevel(buffer.GetByte());
        valRes.GetEvent().SetAccessCredits(buffer.GetByte());
        valRes.SetConferenceLevel(buffer.GetByte());
        valRes.SetFrisk(buffer.GetByte());

        // se a senha é válida seta que a pessoa usa senha
        BYTE Password[6];
        buffer.GetBytes(Password, 6);
        valRes.SetPassword(Password);

        buffer.GetByte(); // BYTE nFlags não utilizado
        buffer.GetByte(); // BYTE nCreditControlType não utilizado

        DLOG_INFO("\nRETORNO DO SERVIDOR (VALIDACAO)\n"
                  "Level: %d\n"
                  "AccessCreditRange: %d\n"
                  "ConferenceLevel: %d (%s)\n"
                  "Revista: %d\n"
                  "Tipo de cartao: %d\n\n",
                  valRes.GetEvent().GetLevel(), valRes.GetEvent().GetAccessCredits(),
                  valRes.GetConferenceLevel(),
                  valRes.CardCheckBiometry() ? "VALIDA BIOMETRIA"
                                             : "NAO VALIDA BIOMETRIA",
                  valRes.GetFrisk(), m_CardType);
    } break;
    }
}

BYTE CSmartCardLogicalIDValidation::CalcNextLevel(BYTE nOriginalLevel)
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
    return readerLevel2;
}

void CSmartCardLogicalIDValidation::DefaultValidation(bool bOnLineValidation,
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
    if (pReaderConfig->CheckList() || !bOnLineValidation || fOnlineCheckList) {
        if (!m_pContext->GetAuthorizedCardList()->LogicalIDContains(
                m_LogicalNumber, m_eReader, CardType)) {
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

    if (!bOnLineValidation || fOnlineCheckList) {
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

void CSmartCardLogicalIDValidation::PrepareSmartCard()
{

    CMCA::ECardReader eCardReader = (CMCA::ECardReader)m_eReader;
    CCardReader *pCardReader = m_pContext->GetMCA()->GetCardReader(eCardReader);
    // Limpa os buffers e associa um novo identificador
    m_pSmartCardHandler->Reset(m_Card, &m_pContext->GetConfiguration()->GetSmartCardMap(),
                               (CSmartCardReader *)pCardReader);
    // pode formatar o cartao
    m_pSmartCardHandler->SetCanFormat(true);

    m_pContext->GetConfiguration()->GetSmartCardMap().GetFieldInAccessValidation(
        m_FieldInUse);
    m_pSmartCardHandler->SetUsedFieldList(m_FieldInUse);

    // Faz a coleta do campo...
    CBuffer pLogicalNumber(6); // Tamanho máximo possível...
    pLogicalNumber.SetBigEndian(fUseBigEndian);

    // Define tamanho do campo...
    m_SizeOfFields = m_pSmartCardHandler->GetFieldValue(
        CSmartCardMap::CardNumber, pLogicalNumber.Data(), pLogicalNumber.Limit());

    // Consiste tamanho...
    if (m_SizeOfFields == 0) {
        // Documento sem tamanho ou falha no método!!!
        throw CException::Format("Campo para numero logico na requisicao de "
                                 "acesso nao possui tamanho ou inexistente!");
    } else if ((m_SizeOfFields != LOGICAL_SIZE) &&
               (m_SizeOfFields != LOGICAL_SIZE_TELEMATICA)) {
        // Tamanho campo diferente tamanho informado para tipos!!!
        throw CException::Format("Campo para numero logico no smartcard possui "
                                 "tamanho diferente dos atuais tipos "
                                 "possiveis!");
    }

    // Pega número lógico... (PASSADOS MATRÍCULAS, TELEMÁTICA NO FORMATO DE
    // CARACTERES)
    digicon::CCard card;
    m_pContext->GetProcessSmartCard()->GetEnroll(m_pSmartCardHandler, card);
    m_LogicalNumber = (ULONGLONG)card.GetId();

    DLOG_INFO("Numero logico: %lld\n", m_LogicalNumber);

    // Se não houver informação...
    if (!m_LogicalNumber) {
        // Campo sem valor ou igual a zero!!!
        throw CException::Format("Campo para numero logico na requisicao de "
                                 "acesso nao possui valor ou e igual a zero!");
    }
    // Atualiza instante da validação
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    m_Now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, m_pContext->GetConfiguration()->GetProperties());

    return;
}
}

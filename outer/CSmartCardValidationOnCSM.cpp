#include "CSmartCardValidationOnCSM.h"
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
#include "CSmartCardHandler.h"
#include "CCardReader.h"
#include "CBiometricManager.h"
#include "CProcessSmartCard.h"
#include "CSmartCardValidation.h"

using digicon::CMCA;
using digicon::CCard;
using digicon::CCardReader;
using seguranca::CMCAHelper;
using digicon::CValidationException;
using base::CSocketException;
using seguranca::CSmartCardUpdates;

// TODO: eliminar a necessidade desta constante para acessar o bloco de
// pendencias.
#define REQUEST_ACCESS_BLOCK_SIZE 12

namespace seguranca
{

CSmartCardValidationOnCSM::CSmartCardValidationOnCSM()
    : m_pContext(NULL),                             //
      m_pSmartCardHandler(NULL),                    //
      m_Now(0),                                     //
      m_eReader(NO_CNFG_READER),                    //
      m_nKeyPressed(255),                           //
      m_BioUser(0),                                 //
      m_nFlags(0),                                  //
      m_AccessCreditRange(0),                       //
      m_CreditControlType(0),                       //
      m_CardType(0),                                //
      m_CardTechnology(0), m_iPendenceBufferSize(0) //
{
    m_pSmartCardHandler = new CSmartCardHandler();
    memset(m_FieldInUse, 0, sizeof(m_FieldInUse));
}

CSmartCardValidationOnCSM::~CSmartCardValidationOnCSM()
{
    SAFE_DELETE(m_pSmartCardHandler);
}

CValidationResult CSmartCardValidationOnCSM::ValidateCard(const CCard Card,
                                                          EReader eReader,
                                                          BYTE nKeyPressed,
                                                          CContext *pContext)
{
    m_Buffer.Clear();
    m_BioUser.Clear();
    m_pContext = pContext;
    m_eReader = eReader;
    CFirmwareProperties *pFirmProps = &m_pContext->GetConfiguration()->GetProperties();
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);

    m_nFlags = 0;
    m_CreditControlType = 0;
    m_AccessCreditRange = -1;
    m_iPendenceBufferSize = 0;
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    m_Now = CFirmwareUtil::GMTToLocalDateTime(GMTZeroTime, *pFirmProps);

    m_CardType = CReaderConfig::NONE;
    m_CardTechnology = CCard::CT_Unknown;
    m_nKeyPressed = nKeyPressed;
    m_Card = Card;

    internal_ValidateCard();

    UINT size = m_Buffer.Limit();
    DLOG_INFO("Tamanho de bloco recebido: %d\n", size);

    CValidationResult valRes;
    valRes.GetEvent().SetCard(Card);
    bool bValidAccess = true;
    try {

        // Analisa o resultado da validacao
        ParseValidationData(valRes, m_Buffer);

        // validar pela Lista ?
        if (pReaderConfig->CheckList()) {
            // Byte para verificar qual é o tipo do cartao da lista
            BYTE CardType = CReaderConfig::NONE;

            // validacao pela lista
            if (!m_pContext->GetAuthorizedCardList()->Contains(m_Card, m_eReader,
                                                               CardType)) {
                // MMF - Include Reader for those events 10/02/2016
                valRes.GetEvent().SetReader(m_eReader);
                if (m_pContext->GetAuthorizedCardList()->CardListType() ==
                    CAuthorizedCardList::authorizedList) {
                    throw CEventException(CEvent::ACCESS_DENIED_WHITE_LIST, m_Card);
                } else {
                    throw CEventException(CEvent::ACCESS_DENIED_BLACK_LIST, m_Card);
                }
            }

            // caso nao seja um acesso negado, verifica se foi uma validacao do
            // cartao mestre
            if (GET_PERSON_TYPE(CardType) == CReaderConfig::MASTER_CARD) {
                valRes.GetEvent().SetId(CEvent::ACCESS_MASTER_CARD);
            }
        }
        // TODO Implementar BDCC
        if (m_pContext->GetConfiguration()
                ->GetReaderConfig(eReader)
                .GetBdccPersonTypeValidation(m_CardType - 1)) {

            PrepareSmartCard();

            if (!BdccValidation.CheckBdccCriptoData(m_pContext, m_pSmartCardHandler,
                                                    m_Card)) {
                throw CEventException(CEvent::ACCESS_DENIED_BDCC,
                                      m_pSmartCardHandler->GetCard());
            }
        }

    } catch (CValidationException &ex) {
        ex.Raise();
    } catch (CEventException &ex) {
        valRes.SetEvent(ex.GetEvent());
        valRes.GetEvent().SetReader(m_eReader);
        bValidAccess = false;
    }

    // tipo da pessoa
    valRes.SetCardType(m_CardType);

    // Define o novo nivel
    if (bValidAccess &&
        !pContext->GetConfiguration()->GetFunctionIgnoreLevel(nKeyPressed)) {
        valRes.SetNewLevel(CalcNextLevel(valRes.GetOriginalLevel()));
        valRes.GetEvent().SetLevel(valRes.GetNewLevel());
    } else {
        valRes.SetNewLevel(valRes.GetOriginalLevel());
    }

    if (m_CardTechnology == CCard::CT_Smart) {
        UpdateSmartCard(bValidAccess, valRes);
    }

    return valRes;
}

void CSmartCardValidationOnCSM::internal_ValidateCard()
{
    // recolhe os dados necessarios na validacao
    CBuffer ValRequest;
    PrepareData(ValRequest);
    // faz o pedido de validacao ao driver
    m_pContext->GetOutputSocket()->RequestSizedData(RequestCardValidation, ValRequest,
                                                    m_Buffer);
}

void CSmartCardValidationOnCSM::PrepareData(CBuffer &dest)
{

    int accFieldSize = 0;
    // identificador
    m_Card.GetInternalData(dest);
    // data e hora local
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    UINT now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, m_pContext->GetConfiguration()->GetProperties());
    dest.PutUInt(now);

    PrepareSmartCard();

    // Data do último acesso
    time_t lastAccess = 0;
    accFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        m_pSmartCardHandler, CSmartCardMap::LastPassDate, &lastAccess);
    if (accFieldSize) {
        dest.PutUInt((UINT)lastAccess);
        accFieldSize = 0;
    } else {
        dest.PutUInt(0);
    }
    // Nível atual do cartão
    BYTE CardLevel = 0;
    accFieldSize =
        m_pSmartCardHandler->GetFieldValue(CSmartCardMap::CardAccessLevel, &CardLevel, 1);
    if (accFieldSize) {
        dest.PutByte(CardLevel);
    } else {
        dest.PutByte(0);
    }
    // leitora
    dest.PutByte(m_eReader + 1);
    // identifica se eh feriado
    dest.PutByte(
        m_pContext->GetHolidayList()->Contains(CFirmwareUtil::GetDateInDays(now)));
    // informa a funcao
    dest.PutByte(m_nKeyPressed);
    dest.Flip();
}

void CSmartCardValidationOnCSM::ParseValidationData(CValidationResult &valRes,
                                                    CBuffer &buffer)
{

    // campo: "Ignorar resposta sobre permissão de acesso e validar pela lista?
    // 0 - não, 1 - sim";
    // Não usado neste escopo! Apenas passa...
    buffer.GetByte();

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
        m_iPendenceBufferSize = buffer.GetUInt();

        char personId[PERSONID_SIZE + 1];
        buffer.GetBytes(personId, PERSONID_SIZE);
        personId[PERSONID_SIZE] = 0;
        DLOG_INFO("Person: %s\n", personId);
        valRes.SetPersonId((char *)personId);
    }

    // identificador do evento
    const CEvent::EventCode eventId = (CEvent::EventCode)buffer.GetByte();
    valRes.GetEvent().SetId(eventId);
    // persiste para comparação futura, se houver alteração do ID durante o
    // curso da validação...
    valRes.SetOriginalEventFromCSM(eventId);
    valRes.GetEvent().SetReader(m_eReader);

    // numero de matricula do cartao
    CCard enroll;
    enroll.ParseId(buffer);
    valRes.SetEnroll(enroll);

    // Tipo do cartão
    m_CardType = buffer.GetByte();
    // tecnologia do cartao
    m_CardTechnology = buffer.GetByte();

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

    BYTE bLevel = 0;
    BYTE temp[12];
    UINT beforeEventData = buffer.Position();

    try {
        // identifica se eh um acesso valido
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
        case CEvent::ACCESS_DENIED_INTERJOURNEY:
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_LUNCH_INTERVAL:
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_FAULT:
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
            break;
        case CEvent::ACCESS_DENIED_VALIDITY: {
            UINT pExpirationDate = buffer.GetUInt(); // Validade do cartao
            valRes.GetEvent().SetValidity(pExpirationDate);
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 7);
            throw CEventException(valRes.GetEvent());
        }
        case CEvent::ACCESS_DENIED_LEVEL:
        case CEvent::ACCESS_DENIED_ANTIPASSBACK:
            valRes.GetEvent().SetFlowType(buffer.GetByte());
            valRes.SetOriginalLevel(buffer.GetByte());
            valRes.GetEvent().SetLevel(valRes.GetOriginalLevel());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 10);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_REMOVAL: {
            UINT start = buffer.GetUInt();
            UINT end = buffer.GetUInt();
            valRes.GetEvent().SetRemovalPeriod(start, end);
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 3);
            throw CEventException(valRes.GetEvent());
        }
        case CEvent::ACCESS_DENIED_PASSWORD:
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 11);
            throw CEventException(valRes.GetEvent());
        case CEvent::ACCESS_DENIED_MIN_TIME:
            valRes.SetOriginalLevel(buffer.GetByte());
            // Apenas passa os bytes não utilizados
            buffer.GetBytes(temp, 11);
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
            valRes.SetOriginalLevel(buffer.GetByte());
            m_AccessCreditRange = buffer.GetByte();
            valRes.SetConferenceLevel(buffer.GetByte());
            valRes.SetFrisk(buffer.GetByte());
            DLOG_INFO("\nRETORNO DO SERVIDOR (VALIDACAO)\n"
                      "Level: %d\n"
                      "AccessCreditRange: %d\n"
                      "ConferenceLevel: %d (%s)\n"
                      "Revista: %d\n"
                      "Tipo de cartao: %d\n\n",
                      valRes.GetOriginalLevel(), m_AccessCreditRange,
                      valRes.GetConferenceLevel(),
                      valRes.CardCheckBiometry() ? "VALIDA BIOMETRIA"
                                                 : "NAO VALIDA BIOMETRIA",
                      valRes.GetFrisk(), m_CardType);

            // se a senha é válida seta que a pessoa usa senha
            BYTE Password[6];
            buffer.GetBytes(Password, 6);
            valRes.SetPassword(Password);
            m_nFlags = buffer.GetByte();
            m_CreditControlType = buffer.GetByte();

        } break;
        }
    } catch (CEventException &ex) {
        m_Buffer.SetPosition(beforeEventData + REQUEST_ACCESS_BLOCK_SIZE);
        ex.Raise();
    }
}

void CSmartCardValidationOnCSM::UpdateSmartCard(const bool bValidAccess,
                                                CValidationResult &valRes)
{
    bool bPendenceUpdated = false;
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);
    CMCA::ECardReader eCardReader = (CMCA::ECardReader)m_eReader;
    CCardReader *pCardReader = m_pContext->GetMCA()->GetCardReader(eCardReader);

    // Verifica se existe mapa do smartcard
    if (m_pContext->GetConfiguration()->GetSmartCardMap().IsEmpty()) {
        if (pReaderConfig->UseDisplay()) {
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

    while (TRUE) {
        try {
            // Limpa os buffers e associa um novo identificador
            m_pSmartCardHandler->Reset(m_Card,
                                       &m_pContext->GetConfiguration()->GetSmartCardMap(),
                                       (CSmartCardReader *)pCardReader);
            // pode formatar o cartao
            m_pSmartCardHandler->SetCanFormat(true);

            // Le a lista de todos os campos que podem ser usados na validacao
            // do acesso
            const CSmartCardMap *pSmartCardMap =
                &m_pContext->GetConfiguration()->GetSmartCardMap();
            pSmartCardMap->GetFieldInAccessValidation(m_FieldInUse);
            m_pSmartCardHandler->SetUsedFieldList(m_FieldInUse);

            // Garantia de que o buffer possue dados para fazer o parser das
            // pendências
            if (m_iPendenceBufferSize > 0) {
                // Faz a atualização do cartao.
                DLOG_INFO("SmartCard possui pendencias\n");

                if ((size_t)m_iPendenceBufferSize !=
                    (m_Buffer.Limit() - m_Buffer.Position())) {
                    // verifique se REQUEST_ACCESS_BLOCK_SIZE está coerente com
                    // o datagrama.
                    DLOG_ERROR("### ERRO \n");
                    throw CException("Problemas no retorno de requisicao de acesso");
                }

                m_pContext->GetProcessSmartCard()->CheckPendencies(m_pSmartCardHandler,
                                                                   m_eReader, m_Buffer);
                bPendenceUpdated = true;
            } else {
                DLOG_INFO("SmartCard sem pendencias\n");
            }

            // Se deu acesso permitido atualiza outros dados do cartão
            if (bValidAccess) {
                UpdateAccessFields(valRes);
            }
        } catch (CDispositiveException &ex) {
            static digicon::CCard LastErrorCard;
            static int CardCounter = 0;
            if (LastErrorCard.GetId() == m_pSmartCardHandler->GetCard().GetId()) {
                CardCounter++;
            } else {
                LastErrorCard = m_pSmartCardHandler->GetCard();
                CardCounter = 0;
            }
            DLOG_WARNING("%d - Erro na leitura do cartao: %s\n", CardCounter,
                         ex.GetMessage());
            if (CardCounter >= 7 || !pCardReader->HasCard()) {
                if (pReaderConfig->GetValidAccessAction().GetUrn().GetAction() == 1) {
                    CAction UrnAction;
                    UrnAction.GetUrn().SetTime(1000);
                    UrnAction.GetUrn().SetAction(1);
                    m_pContext->GetActionManager()->QueueActions(UrnAction);
                }
                CardCounter = 0;
                if (pReaderConfig->UseDisplay() &&
                    !m_pContext->GetActionManager()->IsUsingDisplay())
                    CMCAHelper::TimedDisplay(1000, "Erro na leitura ", "                ",
                                             m_pContext);
                ex.Raise();
            }
            continue;
        } catch (CException &ex) {
            DLOG_WARNING("Erro generico na validacao do acesso\n");
            if (pReaderConfig->UseDisplay() &&
                !m_pContext->GetActionManager()->IsUsingDisplay()) {
                CMCAHelper::TimedDisplay(1200, "Acesso negado   ", "Erro generico   ",
                                         m_pContext);
            }
            ex.Raise();
        }
        break;
    } // while

    try {
        // Salva as modificacoes no cartao
        m_pContext->GetProcessSmartCard()->SaveModifiedData(m_pSmartCardHandler);
    } catch (CException &ex) {
        DLOG_WARNING("Erro na atualizando cartao: %s\n", ex.GetMessage());
        if (pReaderConfig->UseDisplay() &&
            !m_pContext->GetActionManager()->IsUsingDisplay())
            CMCAHelper::TimedDisplay(1000, "Erro na gravacao", "                ",
                                     m_pContext);
        ex.Raise();
    }
    if (bPendenceUpdated) {
        m_pContext->GetProcessSmartCard()->NotifyDriver(m_pSmartCardHandler, m_eReader);
    }
}

void CSmartCardValidationOnCSM::UpdateAccessFields(CValidationResult &valRes)
{
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);

    // Atualizacao da data da ultima passagem
    m_pContext->GetProcessSmartCard()->SetDateTimeField(
        m_pSmartCardHandler, CSmartCardMap::LastPassDate, m_Now);

    // Atualizacao do nivel, somente se a leitora controla o nivel
    if ((pReaderConfig->CheckLevel() || pReaderConfig->CheckAntiPassBack())) {
        BYTE newLevel = valRes.GetNewLevel();
        m_pSmartCardHandler->SetFieldValue(CSmartCardMap::CardAccessLevel, &newLevel, 1);
    }

    // Atualizacao da quantidade de mensagens, a leitora tem q usar display
    if (valRes.GetEvent().GetMessageUsedFlag()) {
        BYTE Messages = 0;
        if (m_pSmartCardHandler->GetFieldValue(CSmartCardMap::MessageExhibitionCounter,
                                               &Messages, 1) == 1) {
            if (Messages > 0) {
                valRes.SetMsgCount(Messages);
                m_pSmartCardHandler->SetFieldValue(
                    CSmartCardMap::MessageExhibitionCounter, &--Messages,
                    sizeof(Messages));
            }
        }
    }

    // Atualizacao dos creditos de acesso
    if (pReaderConfig->GetCreditControl() != CReaderConfig::CC_NOCONTROL &&
        m_AccessCreditRange >= 0 && m_AccessCreditRange <= 6) {
        if (m_CreditControlType == CSmartCardValidation::Control_Range ||
            m_CreditControlType == CSmartCardValidation::Control_Quota) {
            BYTE AccessCredits = 0;
            CSmartCardMap::FieldCode CreditRangeNumber = (CSmartCardMap::FieldCode)(
                CSmartCardMap::RefectoryCreditRange1 + m_AccessCreditRange);
            if (m_pSmartCardHandler->GetFieldValue(CreditRangeNumber, &AccessCredits,
                                                   1) == 1) {
                valRes.SetCreditRange(m_AccessCreditRange + 1);
                valRes.SetCredits(AccessCredits);
                m_pSmartCardHandler->SetFieldValue(CreditRangeNumber, &--AccessCredits,
                                                   1);
            }
        }
        m_pContext->GetProcessSmartCard()->SetDateTimeField(
            m_pSmartCardHandler, CSmartCardMap::LastRefectoryPassDateTime, m_Now);
    }
    // Seta a faixa que teve o consumo de credito, se não teve consumo manda 255
    valRes.GetEvent().SetAccessCredits(m_AccessCreditRange);

    // Atualizacao da data de controle do intervalo de almoco quando for saída
    // Atualização da data de controle da interjornada quando for saída
    if (UPDATE_LUNCHCONTROL_STARDATE(m_nFlags)) {
        // Verifica se o campo existe
        time_t InterJourneyStart = 0;
        int iFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
            m_pSmartCardHandler, CSmartCardMap::LunchControlStartDate,
            &InterJourneyStart);
        valRes.SetLunchControlStartDate(InterJourneyStart);
        if (iFieldSize == 0) {
            DLOG_INFO("[SmartCardValidCSM] no LunchControlStartDate on smart card "
                      "map\n");
        } else {
            m_pContext->GetProcessSmartCard()->SetDateTimeField(
                m_pSmartCardHandler, CSmartCardMap::LunchControlStartDate, m_Now);
        }
    }

    // Se a pessoa e a leitora verificam tempo mínimo de permanência atualizaa
    // data de controle
    if (UPDATE_MINIMUM_STAYTIME(m_nFlags)) {
        // Verifica se o campo existe
        time_t MinimumStayTime = 0;
        int iFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
            m_pSmartCardHandler, CSmartCardMap::MinimumStayTimeDateTime,
            &MinimumStayTime);
        if (iFieldSize == 0) {
            DLOG_INFO("[SmartCardValidCSM] no MinimumStayTimeDateTime on smart "
                      "card map\n");
        } else {
            m_pContext->GetProcessSmartCard()->SetDateTimeField(
                m_pSmartCardHandler, CSmartCardMap::MinimumStayTimeDateTime, m_Now);
        }
    }
}

BYTE CSmartCardValidationOnCSM::CalcNextLevel(BYTE nOriginalLevel)
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

void CSmartCardValidationOnCSM::PrepareSmartCard()
{

    CMCA::ECardReader eCardReader = (CMCA::ECardReader)m_eReader;
    CCardReader *pCardReader = m_pContext->GetMCA()->GetCardReader(eCardReader);
    m_pSmartCardHandler->Reset(m_Card, &m_pContext->GetConfiguration()->GetSmartCardMap(),
                               (CSmartCardReader *)pCardReader);
    m_pSmartCardHandler->SetCanFormat(true);

    m_pContext->GetConfiguration()->GetSmartCardMap().GetFieldInAccessValidation(
        m_FieldInUse);
    m_pSmartCardHandler->SetUsedFieldList(m_FieldInUse);

    return;
}
}

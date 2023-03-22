#include "CIDCardValidation.h"
#include "CActionManager.h"
#include "CAuthorizedCardList.h"
#include "CBiometricManager.h"
#include "CCard.h"
#include "CCardMask.h"
#include "CCardUseIdList.h"
#include "CContext.h"
#include "CDevice.h"
#include "CEventException.h"
#include "CFirmwareUtil.h"
#include "CHolidayList.h"
#include "COutputSocket.h"
#include "CPasswordManager.h"
#include "CPerson.h"
#include "CPersonManager.h"
#include "CSocketException.h"
#include "CStateTable.h"
#include "CUserCodes.h"
#include "CValidationException.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace digicon;
using namespace base;

#define EMPTY_LEVEL 99

#define TRACE_PETROBRAS(argsp...)                                                        \
    fprintf(stdout, "[PETROBRAS] ");                                                     \
    fprintf(stdout, argsp)

#define CT_ULTRALIGHT 8

namespace seguranca
{

CIDCardValidation::CIDCardValidation()
    : m_pContext(NULL),                     //
      m_Now(0),                             //
      m_eReader(NO_CNFG_READER),            //
      m_nKeyPressed(255),                   //
      m_bPersonValidation(false),           //
      m_CardType(0),                        //
      m_CryptoType(0), m_bCheckList(false), //
      m_CardTechnology(0), m_IsDocumentValidation(false)
{
}

CIDCardValidation::~CIDCardValidation() {}

CValidationResult CIDCardValidation::ValidateCard(const digicon::CCard Card,
                                                  EReader eReader, BYTE nKeyPressed,
                                                  CContext *pContext)
{
    CValidationResult valRes;
    m_pContext = pContext;
    m_eReader = eReader;
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);
    CDevice *pConfig = pContext->GetConfiguration();

    // data e hora local
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    m_Now = CFirmwareUtil::GMTToLocalDateTime(
        GMTZeroTime, pContext->GetConfiguration()->GetProperties());

    m_Buffer.SetLimit(0);
    m_nKeyPressed = nKeyPressed;
    m_Card = Card;
    m_bPersonValidation = (Card.GetTecnology() == CCard::CT_Person);
    m_CardType = CReaderConfig::NONE;
    m_CardTechnology = CCard::CT_Unknown;

    m_CryptoType = pConfig->GetCryptType();

    // Validate if Token
    if (!validateToken(valRes)) {
        valRes.GetEvent().SetCard(Card);
        return valRes;
    }

    DLOG_INFO("ID buffer length: %u\n", m_Card.GetIdBufferLength());
    DLOG_INFO("ID numerico: %llu\n", m_Card.GetId());

    if (m_Card.GetIdBufferLength() > 0 ||
        (m_Card.GetId() > 0xffffffffffULL && !m_bPersonValidation)) {
        m_IsDocumentValidation = true;
    } else {
        m_IsDocumentValidation = false;
    }

    DLOG_INFO("Validacao por documento: %s\n", m_IsDocumentValidation ? "Sim" : "Nao");

    // Online e sem estar no modo "Quiet"?
    if (m_pContext->GetOutputSocket()->HasCSMComm() &&
        !m_pContext->GetOutputSocket()->IsQuietMode()) {
        internal_ValidateEntity();
    }
    // se houver dados no buffer, entao a validacao foi online
    const bool bOnLineValidation = (m_Buffer.Limit() > 0);
    //----------------------------------------------------
    CAccessEvent ae;
    ae.SetId(CEvent::ACCESS_GRANTED);
    ae.SetLevel(EMPTY_LEVEL);
    ae.SetAccessCredits(0xFF);
    ae.SetReader(m_eReader);
    //---------------------------------------------
    bool bValidAccess = true;
    valRes.SetEvent(ae);
    // Identifica a entrada da validacao
    if (Card.GetTecnology() == CCard::CT_Person) {
        valRes.GetEvent().SetPersonId(Card.GetPerson());
        valRes.SetPersonId(Card.GetPerson());
    } else {
        valRes.GetEvent().SetCard(Card);
    }

    try {
        if (bOnLineValidation) {
            // analisa o resultado da validacao
            CBuffer buffer(m_Buffer);

            ParseValidationData(valRes, buffer);

            // Testa a opção por configuração de checar a lista,
            // obrigatoriamente,
            // caso isso ainda tenha retornado "falso" pela resposta à
            // requisição de acesso...
            if (!m_bCheckList) {
                m_bCheckList = pReaderConfig->CheckList() ? true : false;
            }
        } else {
            // Quando offline, a validação pela lista é obrigatória.
            m_bCheckList = true;
        }

        bool checkForeignSubsidiary =
            !bOnLineValidation && pReaderConfig->CheckForeignSubsidiaryControl();
        DLOG_INFO("Controla filial estrangeira: %s\n",
                  checkForeignSubsidiary ? "sim" : "nao");
        if (checkForeignSubsidiary) {
            if (!ValidateForeignSubsidiary(valRes)) {
                validacaoPadrao(bOnLineValidation, valRes);
            }
        } else {
            // validar pela Lista ?
            if (m_bCheckList) {
                validacaoPadrao(bOnLineValidation, valRes);
            }
        }

    } catch (CValidationException &ex) {
        ex.Raise();
    } catch (CEventException &ex) {
        valRes.SetEvent(ex.GetEvent());
        bValidAccess = false;
        // segue normalmente...
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

    return valRes;
}

void CIDCardValidation::validacaoPadrao(bool bOnLineValidation, CValidationResult &valRes)
{
    CReaderConfig *pReaderConfig =
        &m_pContext->GetConfiguration()->GetReaderConfig(m_eReader);
    CAction UrnAction;
    bool m_bIsActiveBlockType = false;
    // se a validacao eh off-line, deve-se encontrar o cartao da pessoa
    if (m_bPersonValidation) {
        if (!bOnLineValidation) {
            CPerson person(m_Card.GetPerson());
            if (m_pContext->GetPersonManager()->FindPerson(m_Card.GetPerson(), person)) {
                if (person.Cards().size() > 0) {
                    m_Card = person.Cards().at(0);
                    valRes.GetEvent().SetCard(m_Card);
                    valRes.SetConferenceLevel(person.GetConferenceLevel());
                } else {
                    DLOG_INFO("PESSOA NAO POSSUI CARTAO CADASTRADO (lista RE)\n");
                    CDisplay::DisplayText Message = {};
                    memcpy(Message.line1, "Pessoa sem      ", 16);
                    memcpy(Message.line2, "Cartao          ", 16);
                    throw CValidationException(2, Message);
                }
            } else {
                DLOG_INFO("PESSOA NAO CADASTRADA (lista RE)\n");
                CDisplay::DisplayText Message;
                memset(&Message, 0, sizeof(Message));
                memcpy(Message.line1, "Pessoa nao      ", 16);
                memcpy(Message.line2, "Cadastrada      ", 16);
                throw CValidationException(1, Message);
            }
        }
    } else {
        if (strlen(valRes.GetPersonId()) == 0) {
            // Se for validação de cartão, tenta encontrar a pessoa referente ao
            // cartao
            CPerson person;
            if (m_pContext->GetPersonManager()->FindPersonByCard(m_Card, person)) {
                valRes.SetPersonId(person.GetId());
                valRes.SetConferenceLevel(person.GetConferenceLevel());
            }
        }
    }

    // Byte para verificar qual é o tipo do cartao da lista
    BYTE CardType = CReaderConfig::NONE;

    // validacao pela lista
    if (!m_pContext->GetAuthorizedCardList()->Contains(m_Card, m_eReader, CardType)) {
        if (m_pContext->GetAuthorizedCardList()->CardListType() ==
            CAuthorizedCardList::authorizedList) {
            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_WHITE_LIST);
        } else {
            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_BLACK_LIST);
        }
        throw CEventException(valRes.GetEvent());
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
                    if (BlockType == 0) {
                        if (pReaderConfig->GetBlockPersonTypeValidation(m_CardType - 1) ==
                            2) {
                            if (!m_pContext->IsOnline()) {
                                m_bIsActiveBlockType = true;
                                DLOG_INFO("Offline Pass\n");
                            } // offline
                        } else {
                            DLOG_INFO("Default Bloqueado\n");

                            DLOG_INFO("Acesso Negado por Tipo de Pessoa %d\n",
                                      m_CardType - 1);
                            valRes.SetEvent(CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT);
                            valRes.GetEvent().SetId(
                                CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT);
                        }
                    }

                    if (((BlockType >> (CardType - 1)) & 1) == 0) {
                        if (!m_bIsActiveBlockType) {
                            DLOG_INFO("Cartao bloqueado na saida\n");
                            throw CEventException(CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT,
                                                  m_Card);
                        }
                    }
                }
            }
        }

        // caso nao seja um acesso negado, verifica se foi uma validacao do
        // cartao mestre
        if (GET_PERSON_TYPE(CardType) == CReaderConfig::MASTER_CARD) {
            // Cartão mestre nao valida biometria
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
    } // end offline
}

bool CIDCardValidation::validateToken(CValidationResult &res)
{
    bool bRes = false;
    CDisplay::DisplayText Message;
    memset(&Message, 0, sizeof(Message));

    if (m_Card.GetJWTStatus() != CCard::JWT_OK) {
        CAccessEvent jwtEvent;
        jwtEvent.SetLevel(EMPTY_LEVEL);
        jwtEvent.SetAccessCredits(0xFF);
        jwtEvent.SetReader(m_eReader);

        // Verifica se o CCard é um Token tipo JWT inválido. Caso verdadeiro, significa
        // que deve lançar as exceções e eventos apropriados ao STATUS retornado. Caso
        // contrário segue com a validação normalmente
        switch (m_Card.GetJWTStatus()) {
        case CCard::JWT_OK:
            DLOG_INFO("CCard JWT type: Token is Valid!\n");
            bRes = true;
            break;
        case CCard::JWT_BAD_ISSUER:
            DLOG_ERROR("CCard JWT type: Bad Issuer!\n");
            jwtEvent.SetId(CEvent::ACCESS_DENIED_SUBSIDIARY);
            memcpy(Message.line1, "Token invalido  ", 16);
            memcpy(Message.line2, "Orig. desconhec.", 16);
            break;
        case CCard::JWT_EXIPRATION_TIME:
            DLOG_ERROR("CCard JWT type: Expiration Time!\n");
            jwtEvent.SetId(CEvent::ACCESS_DENIED_PERSON_HOURLYRANGE);
            memcpy(Message.line1, "Token invalido  ", 16);
            memcpy(Message.line2, "tempo expirado..", 16);
            break;
        case CCard::JWT_NOT_BEFORE_TIME:
            DLOG_ERROR("CCard JWT type: Not Before Time!\n");
            jwtEvent.SetId(CEvent::ACCESS_DENIED_PERSON_HOURLYRANGE);
            memcpy(Message.line1, "Token invalido  ", 16);
            memcpy(Message.line2, "ainda n. vigente", 16);
            break;
        }

        // Verifica ser Usa display. Caso contrário, enviar uma mensagem para o mesmo pode
        // travar o firmware.
        if (m_pContext->GetConfiguration()->GetReaderConfig(m_eReader).UseDisplay()) {
            CAction action;
            action.GetDisplay().SetAction(1);
            action.GetDisplay().SetTime(2000);
            action.SetDisplayMsg(&Message);
            action.GetBuzzer().SetAction(1);
            action.GetBuzzer().SetTime(1000);
            m_pContext->GetActionManager()->QueueActions(action);
        }
        res.SetEvent(jwtEvent);
    } else {
        DLOG_INFO("CCard JWT type: Token is Valid!\n");
        bRes = true;
    }

    return bRes;
}

bool CIDCardValidation::ValidateForeignSubsidiary(CValidationResult &valRes)
{

    const char *pCardMask = m_pContext->GetConfiguration()->GetCardMask();
    CCardMask cardMask;
    cardMask.Parse(pCardMask, strlen(pCardMask));

    // Extrair identificador de uso do cartão
    int cardUseId =
        cardMask.IntValue(CCardMaskToken::CARD_USE_IDENTIFIER, m_Card.GetId());
    TRACE_PETROBRAS("Card use id: %d\n", cardUseId);

    // encontrar uso do cartão a partir do identificador
    int cardUse = m_pContext->GetCardUseIdList()->GetCardUseFromId(cardUseId);
    TRACE_PETROBRAS("Card use: %d\n", cardUse);

    // verificar se é empregado {
    if (GET_PERSON_TYPE(cardUse) == CReaderConfig::EMPLOYEE) {
        BYTE CardType = 0;
        TRACE_PETROBRAS("Empregado: Sim\n");

        if (m_pContext->GetAuthorizedCardList()->CardListType() ==
            CAuthorizedCardList::authorizedList) {
            // LIBERAÇÃO
            TRACE_PETROBRAS("LISTA LIBERACAO\n");
            if (!m_pContext->GetAuthorizedCardList()->Contains(m_Card, m_eReader,
                                                               CardType)) {
                // MMF - Include Reader for those events 10/02/2016
                valRes.GetEvent().SetReader(m_eReader);
                // extrair filial
                int subsidiaryId =
                    cardMask.IntValue(CCardMaskToken::SUBSIDIARY, m_Card.GetId());
                TRACE_PETROBRAS("Filial cartao: %d, local: %d\n", subsidiaryId,
                                m_pContext->GetConfiguration()->GetSubsidiaryId());
                if (subsidiaryId == m_pContext->GetConfiguration()->GetSubsidiaryId()) {
                    // Eh funcionario local e está bloqueado
                    throw CEventException(CEvent::ACCESS_DENIED_WHITE_LIST, m_Card);
                }
                // empregado de outra filial deixa seguir
            }

        } else {
            // BLOQUEIO
            TRACE_PETROBRAS("LISTA BLOQUEIO\n");
            if (!m_pContext->GetAuthorizedCardList()->Contains(m_Card, m_eReader,
                                                               CardType)) {
                throw CEventException(CEvent::ACCESS_DENIED_BLACK_LIST, m_Card);
            }
        }

        return true;
    }
    return false;
}

BYTE CIDCardValidation::GetDataKind() const
{
    if (m_IsDocumentValidation) {
        return RequestDocumentValidation;
    } else if (m_bPersonValidation) {
        return RequestPersonValidation;
    } else {
        return RequestCardValidation;
    }
}

void CIDCardValidation::internal_ValidateEntity()
{
    // recolhe os dados necessarios na validacao
    /* TODO: O buffer foi definido para 1050, por questões da requisição de
     *documento. 1024 bytes para o barcode
     *		 1050 porque 1024 + o restante da requisição
     */
    CBuffer ValRequest(1050);
    PrepareData(ValRequest);

    // faz o pedido de validacao ao driver
    CBuffer buffer(m_Buffer);
    m_pContext->GetOutputSocket()->RequestSizedData((DataKind)GetDataKind(), ValRequest,
                                                    buffer);
}

void CIDCardValidation::PrepareData(CBuffer &dest)
{
    // Documento
    BYTE DocType = 0;
    WORD Length = 0; // Atualizado campo de acordo com o protocolo 6.8

    // identificador
    if (m_IsDocumentValidation) {
        if (m_Card.GetIdBufferLength() > 0) {
            DocType = (BYTE)DT_BarCode;
            Length = (WORD)m_Card.GetIdBufferLength();
        } else {
            DocType = (BYTE)DT_Mifare;
            Length = (WORD)sizeof(ULONGLONG);
        }

        dest.PutByte(DocType);
        dest.PutWord(Length);

        if (m_Card.GetIdBufferLength() > 0) {
            dest.PutBytes(m_Card.GetIdBuffer(), Length);
        } else {
            dest.PutULLId(m_Card.GetId());
        }
    } else if (m_bPersonValidation) {
        dest.PutBytes(m_Card.GetPerson(), PERSONID_SIZE);
    } else {
        m_Card.GetInternalData(dest);
    }
    //	Data e hora local
    dest.PutUInt((UINT)m_Now);
    // Data do último acesso
    dest.PutUInt(0);
    //	Nível atual do cartão
    dest.PutByte(0);
    // leitora
    dest.PutByte(m_eReader + 1);
    // identifica se eh feriado
    dest.PutByte(
        m_pContext->GetHolidayList()->Contains(CFirmwareUtil::GetDateInDays(m_Now)));
    // informa a funcao
    dest.PutByte(m_nKeyPressed);
    dest.Flip();
}

void CIDCardValidation::ParseValidationData(CValidationResult &valRes, CBuffer &buffer)
{

    // campo: "Ignorar resposta sobre permissão de acesso e validar pela lista?
    // 0 - não, 1 - sim";
    m_bCheckList = (buffer.GetByte() == 1) ? true : false;
    // tipo de retorno
    const EValReturnType eReturnType = (EValReturnType)buffer.GetByte();
    char personId[PERSONID_SIZE + 1];

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
    } else if (eReturnType == VR_Card) { //	Não utiliza pois aqui só entra
        // cartões de barras e RFID
        buffer.GetUInt(); // UINT PendenceBufferSize

        //	char personId[PERSONID_SIZE + 1];
        buffer.GetBytes(personId, PERSONID_SIZE);
        personId[PERSONID_SIZE] = 0;
        DLOG_INFO("Person: %s\n", personId);
        valRes.SetPersonId((char *)personId);
    } else {
        valRes.SetPersonId(m_Card.GetPerson());
    }

    //	identificador do evento
    CEvent::EventCode eventId = (CEvent::EventCode)buffer.GetByte();
    valRes.GetEvent().SetId(eventId);
    //	persiste para comparação futura, se houver alteração do ID durante o
    // curso da validação...

    valRes.SetOriginalEventFromCSM(eventId);
    valRes.GetEvent().SetReader(m_eReader);

    //	Caso a resposta mande validar pela lista, "desconsidera" a resposta da
    // validação usando a resposta padrão!
    if (m_bCheckList) {
        eventId = (CEvent::EventCode)CAccessEvent::ACCESS_GRANTED;
        valRes.GetEvent().SetId(eventId);
    }

    if (m_bPersonValidation) {
        m_Card.ParseId(buffer);
        /*	O método SetCard aqui está definindo errado o tipo de
           validação...
                valRes.GetEvent().SetCard(m_Card);	*/
    }

    // numero de matricula do cartao
    CCard enroll;
    enroll.ParseId(buffer);
    valRes.SetEnroll(enroll);
    DLOG_INFO("Card ID [%llX]\n", valRes.GetEvent().GetCard().GetId());

    if (m_IsDocumentValidation) {
        ULONGLONG temp = enroll.GetId();
        uint32_t m_uiCastID = (uint32_t)temp;
        enroll.SetId(m_uiCastID);
        valRes.SetEnroll(enroll);
        valRes.GetEvent().SetCard(enroll);
        valRes.GetEvent().GetCard();
        DLOG_INFO("ID Logico [%llX]\n", valRes.GetEvent().GetCard().GetId());
    }

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
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // Acesso negado por interjornada de trabalho
    case CEvent::ACCESS_DENIED_INTERJOURNEY:
        valRes.SetOriginalLevel(buffer.GetByte());
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // Acesso negado intervalo de almoco
    case CEvent::ACCESS_DENIED_LUNCH_INTERVAL:
        valRes.SetOriginalLevel(buffer.GetByte());
        //	Apenas passa os bytes não utilizados
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
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 7);
        throw CEventException(valRes.GetEvent());
    // acesso negado nivel
    case CEvent::ACCESS_DENIED_LEVEL:
    case CEvent::ACCESS_DENIED_ANTIPASSBACK:
        valRes.GetEvent().SetFlowType(buffer.GetByte());
        valRes.SetOriginalLevel(buffer.GetByte());
        valRes.GetEvent().SetLevel(valRes.GetOriginalLevel());
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 10);
        throw CEventException(valRes.GetEvent());
    // acesso negado afastamento
    case CEvent::ACCESS_DENIED_REMOVAL: {
        UINT start = buffer.GetUInt();
        UINT end = buffer.GetUInt();
        valRes.GetEvent().SetRemovalPeriod(start, end);
        valRes.SetOriginalLevel(buffer.GetByte());
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 3);
        throw CEventException(valRes.GetEvent());
    }
    // acesso negado senha
    case CEvent::ACCESS_DENIED_PASSWORD:
        valRes.SetOriginalLevel(buffer.GetByte());
        //	Apenas passa os bytes não utilizados
        buffer.GetBytes(temp, 11);
        throw CEventException(valRes.GetEvent());
    // acesso negado tempo minimo de permanencia
    case CEvent::ACCESS_DENIED_MIN_TIME:
        valRes.SetOriginalLevel(buffer.GetByte());
        //	Apenas passa os bytes não utilizados
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

        //	se a senha é válida seta que a pessoa usa senha
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

BYTE CIDCardValidation::CalcNextLevel(BYTE nOriginalLevel)
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

bool CIDCardValidation::HasAlpha(BYTE barcode[], UINT size)
{
    bool isAlpha = false;
    BYTE Numerics[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    int k = 0;

    for (unsigned int i = 0; i < size; i++) {
        k = 0;
        while (Numerics[k] != barcode[i]) // 0 - 1 true
        {
            if (k == 10) {
                isAlpha = true;
                k = 0;
                break;
            }
            k += 1;
        }
    }

    return isAlpha;
}

bool CIDCardValidation::HasAscii(BYTE barcode[], UINT size)
{
    bool isAsc = false;
    BYTE Asc[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    int k = 0;

    for (unsigned int i = 0; i < size; i++) {
        k = 0;
        while (Asc[k] != barcode[i]) // 0 - 1 true
        {
            if (k == 10) {
                isAsc = true;
                k = 0;
                break;
            }
            k += 1;
        }
    }

    return isAsc;
}
} // namespace seguranca

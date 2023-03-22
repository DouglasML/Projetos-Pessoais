#include "CRecognitionValidation.h"
#include "CActionManager.h"
#include "CAuthorizedCardList.h"
#include "CCard.h"
#include "CCardReader.h"
#include "CContext.h"
#include "CDevice.h"
#include "CEventException.h"
#include "CFirmwareUtil.h"
#include "CHolidayList.h"
#include "CMCA.h"
#include "CMCAHelper.h"
#include "COutputSocket.h"
#include "CPersonManager.h"
#include "CPlate.h"
#include "CRecognitionManager.h"
#include "CRecognitionSocket.h"
#include "CSocketException.h"
#include "CUserCodes.h"
#include "CValidationException.h"
#include "dlog.h"
#include <unistd.h>

using base::CSocketException;
using digicon::CCard;
using digicon::CCardReader;
using digicon::CMCA;
using digicon::CValidationException;
using seguranca::CMCAHelper;

#define CPF_SIZE 5
#define PASSPORT_SIZE 5
#define RENAVAM_SIZE 5
#define LOGICAL_SIZE 5
#define LOGICAL_SIZE_TELEMATICA 6

namespace seguranca
{

CRecognitionValidation::CRecognitionValidation()
    : m_pContext(NULL),                            //
      m_eReader(NO_CNFG_READER),                   //
      m_nKeyPressed(255),                          //
      m_CardType(0),                               //
      m_CardTechnology(0),                         //
      m_SizeOfFields(0),                           //
      m_RecognitionNumber(0LL),                    //
      m_Now(0),                                    //
      m_TimeOutLPR(0), m_bPersonValidation(false), //
      m_bUseBigEndian(false),                      //
      m_bOnlineCheckList(false),                   //
      m_bWaitingForAnOfflineCard(CT_NONE)
{
    m_PlateBetweenCards.SetEnabledReaders(0);
    m_PlateBetweenCards.SetValidationType(0);
    char Plate[5] = {0};
    m_PlateBetweenCards.setId(Plate);
    m_PlateBetweenCards.ConductorCards().clear();
    m_PlateBetweenCards.VehicleCards().clear();
}

CRecognitionValidation::~CRecognitionValidation()
{
    //	SAFE_DELETE( m_pSmartCardHandler );
}

CValidationResult CRecognitionValidation::ValidateCard(const CCard Card, EReader eReader,
                                                       BYTE nKeyPressed,
                                                       CContext *pContext)
{

    m_Buffer.Clear();
    m_pContext = pContext;
    m_eReader = eReader;

    m_CardType = CReaderConfig::NONE;
    m_CardTechnology = CCard::CT_Unknown;
    m_nKeyPressed = nKeyPressed;
    // IDs não estão vindo zerados? TODO: revisar com Marcel o porquê de haver
    // placa em um novo cartão que era pra vir zerado (sem servidor de
    // reconhecimento ativo)...
    char PlateZero[6] = {0};
    char PersonZero[24] = {0};
    m_Card.SetPlate(PlateZero);
    m_Card.SetId(0LL);
    m_Card.SetTecnology(CCard::CT_Unknown);
    m_Card.SetPerson(PersonZero);

    m_Card = Card;

    m_bPersonValidation = (Card.GetTecnology() == CCard::CT_Person);

    //----------------------------------------------------
    CAccessEvent ae;
    ae.SetId(CEvent::ACCESS_GRANTED);
    // ae.GetId();
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
        // Se evento pendente, servidor de reconhecimento online! Salva ID de
        // placa vinda...
        //		if
        //(m_pContext->GetRecognitionSocket()->HasRecognitionEvent()){
        ////Passado ao Manager...
        if (m_pContext->GetRecognitionManager()->HasRecognitionEvent()) {
            //		m_Card.SetPlate(pContext->GetRecognitionSocket()->GetPlate());
            ////Passado ao Manager...
            m_Card.SetPlate(pContext->GetRecognitionManager()->GetIDPlate());
            // valRes.GetEvent().SetRecognitionId(m_Card.GetPlate());
        } else {
            // Se servidor de reconhecimento desconectado, placa é zerada...
            m_Card.SetPlate(PlateZero);
        }
    }

    bool bValidAccess = true;

    if (m_pContext->IsOnline() && !m_pContext->GetOutputSocket()->IsQuietMode() &&
        (m_bWaitingForAnOfflineCard == CT_NONE)) {
        // Prepara e requisita o acesso à concentradora...
        internal_ValidateCard();

        if (m_Buffer.Limit() > 0) {
            DLOG_INFO("Tamanho de bloco recebido: %d \n", m_Buffer.Limit());

            try {
                // Analisa o resultado da validacao
                ParseValidationData(valRes, m_Buffer);

            } catch (CValidationException &ex) {
                ex.Raise();
            } catch (CEventException &ex) {
                valRes.SetEvent(ex.GetEvent());
                DLOG_ERROR("<RCGNT_V> ParseValidationData Caiu na excessão para o "
                           "evento informado acima");
                bValidAccess = false;
            }
        } else {
            DLOG_WARNING("\n\n\nFALHA NO RETORNO DA REQUISICAO DE ACESSO!!!\n");
            DLOG_WARNING("\nValidando apenas pela lista local...\n\n\n");
        }

    } else {                        // Validação é offline
        if (!m_bPersonValidation) { // Validação de PLACA ou CARTÃO...
            CPlate ReturnPlate;

            // Se ocorreu o TimeOut da validação entre cartões, altera a flag
            // para o default...
            if ((m_bWaitingForAnOfflineCard != CT_NONE) &&
                IsTimeOutLPR(m_pContext->GetConfiguration()->GetTimeOutLPRValidation())) {
                m_bWaitingForAnOfflineCard = CT_NONE;
            }

            if (m_bWaitingForAnOfflineCard ==
                CT_NONE) { // Se não ocorreu validação de cartão com a espera de
                           // outro...
                // Se houver ID de placa e evento tiver pendente do servidor de
                // reconhecimento é LPR...
                if (m_pContext->GetRecognitionManager()->HasRecognitionEvent()) {
                    if (m_pContext->GetRecognitionManager()->FindPlate(m_Card.GetPlate(),
                                                                       ReturnPlate)) {
                        DLOG_INFO("Placa encontrada!\n");
                        // Testar se leitora corrente está habilitada para o
                        // caso...
                        if (!IsEnabledReader(eReader, ReturnPlate.GetEnabledReaders())) {

                            DLOG_INFO("Leitora nao habilitada para esta validacao!\n");
                            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CARDUSEID);
                            bValidAccess = false;
                            return valRes;
                        }

                        // Participa do controle LPR?**** Aqui já estaria no
                        // controle, não faz sentido! Tirar este "if" ou fazer
                        // lógica de bits...
                        if (ReturnPlate.GetValidationType() & CPlate::VT_LPR) {

                            char Plate[5];
                            memcpy(&Plate, ReturnPlate.GetId(), 5);
                            DLOG_INFO("Veiculo esta no controle LPR, placa "
                                      "%c%c%c%02x%02x . Verificando se pertence a "
                                      "frota...",
                                      Plate[0], Plate[1], Plate[2],
                                      (unsigned char)Plate[3], (unsigned char)Plate[4]);
                            //É veículo da frota?
                            if (ReturnPlate.GetValidationType() & CPlate::VT_FLEET) {

                                // Solicita a passagem do crachá do condutor...
                                char Plate[5];
                                memcpy(&Plate, ReturnPlate.GetId(), 5);
                                DLOG_INFO("Veiculo pertence a frota, placa "
                                          "%c%c%c%02x%02x . Solicitando a passagem "
                                          "do cracha do condutor...",
                                          Plate[0], Plate[1], Plate[2],
                                          (unsigned char)Plate[3],
                                          (unsigned char)Plate[4]);
                                valRes.GetEvent().SetId(
                                    CEvent::ACCESS_DENIED_WAITING_CONDUCTOR);
                                // Indica que é tipo veículo...
                                m_bWaitingForAnOfflineCard = CT_CONDUCTOR;
                                // inicia contagem de tempo de mora entre
                                // cartões...
                                m_TimeOutLPR = CFirmwareUtil::GetTickCount();
                                //								m_PlateBetweenCards.setId(Plate);
                                m_PlateBetweenCards = ReturnPlate;
                                bValidAccess = false;
                            } else {
                                DLOG_INFO("Veiculo nao pertence a uma frota! "
                                          "Liberando acesso...");
                                valRes.GetEvent().SetId(CEvent::ACCESS_GRANTED_VEHICLE);
                                bValidAccess = true;
                            }
                        }

                    } else {
                        DLOG_INFO("Placa nao encontrada na lista! Negando acesso...\n");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_VEHICLE);
                        bValidAccess = false;
                        return valRes;
                    }

                } else { // aqui entra validação direta com cartão...
                    // Se encontrar cartão do veículo na lista...
                    if (m_pContext->GetRecognitionManager()->FindPlateByVehicleCard(
                            m_Card, ReturnPlate)) {
                        // Testar se leitora corrente está habilitada para o
                        // caso...
                        if (!IsEnabledReader(eReader, ReturnPlate.GetEnabledReaders())) {

                            DLOG_INFO("Leitora nao habilitada para esta validacao!\n");
                            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_VEHICLE);
                            bValidAccess = false;
                            return valRes;
                        }

                        // Solicita a passagem do crachá do condutor...
                        char Plate[5];
                        memcpy(&Plate, ReturnPlate.GetId(), 5);
                        DLOG_INFO("Encontrado cartao de veiculo de placa "
                                  "%c%c%c%02x%02x, solicitando a passagem do cracha "
                                  "do condutor...",
                                  Plate[0], Plate[1], Plate[2], (unsigned char)Plate[3],
                                  (unsigned char)Plate[4]);
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_WAITING_CONDUCTOR);
                        //						//Indica que é
                        // tipo veículo...
                        //						valRes.SetCardType(16);
                        m_bWaitingForAnOfflineCard = CT_CONDUCTOR;
                        // inicia contagem de tempo de mora entre cartões...
                        m_TimeOutLPR = CFirmwareUtil::GetTickCount();
                        //						m_PlateBetweenCards.setId(Plate);
                        m_PlateBetweenCards = ReturnPlate;

                        // Se for o cartão do condutor...
                    } else if (m_pContext->GetRecognitionManager()
                                   ->FindPlateByConductorCard(m_Card, ReturnPlate)) {

                        // Testar se leitora corrente está habilitada para o
                        // caso...
                        if (!IsEnabledReader(eReader, ReturnPlate.GetEnabledReaders())) {

                            DLOG_INFO("Leitora nao habilitada para esta validacao!\n");
                            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CONDUCTOR);
                            bValidAccess = false;
                            return valRes;
                        }

                        // Solicita a passagem do crachá do veículo...
                        char Plate[5];
                        memcpy(&Plate, ReturnPlate.GetId(), 5);
                        DLOG_INFO("Encontrado cartao do condutor para placa "
                                  "%c%c%c%02x%02x, solicitando a passagem do cracha "
                                  "do veiculo...",
                                  Plate[0], Plate[1], Plate[2], (unsigned char)Plate[3],
                                  (unsigned char)Plate[4]);
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_WAITING_VEHICLE);
                        m_bWaitingForAnOfflineCard = CT_VEHICLE;
                        // inicia contagem de tempo de mora entre cartões...
                        m_TimeOutLPR = CFirmwareUtil::GetTickCount();
                        //						m_PlateBetweenCards.setId(Plate);
                        m_PlateBetweenCards = ReturnPlate;

                    } else { // Cartão não encontrado...
                        DLOG_INFO("Cartao de veiculo ou condutor nao encontrado! "
                                  "Negando acesso...");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CARDUSEID);
                    }
                }
                bValidAccess = false;

            } else { // Aqui já ocorreu a validação do primeiro cartão, segue
                     // para o segundo...

                if (m_pContext->GetRecognitionManager()->FindPlateByConductorCard(
                        m_Card, ReturnPlate)) {

                    if (!IsEnabledReader(eReader, ReturnPlate.GetEnabledReaders())) {

                        DLOG_INFO("Leitora nao habilitada para esta validacao!\n");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CONDUCTOR);
                        bValidAccess = false;
                        return valRes;
                    }

                    // Confirmando que achou cartão para mesma placa...
                    if (!strcmp(m_PlateBetweenCards.GetId(), ReturnPlate.GetId())) {
                        // Se cartão em espera era realmente condutor...
                        if (m_bWaitingForAnOfflineCard == CT_CONDUCTOR) {
                            char Plate[5];
                            memcpy(&Plate, ReturnPlate.GetId(), 5);
                            DLOG_INFO("Encontrado cartao do condutor para placa "
                                      "%c%c%c%02x%02x. Acesso PERMITIDO!",
                                      Plate[0], Plate[1], Plate[2],
                                      (unsigned char)Plate[3], (unsigned char)Plate[4]);
                            valRes.GetEvent().SetId(CEvent::ACCESS_GRANTED_CONDUCTOR);
                            bValidAccess = true;
                        } else {

                            char Plate[5];
                            memcpy(&Plate, ReturnPlate.GetId(), 5);
                            DLOG_INFO("Cartao encontrado para placa %c%c%c%02x%02x. "
                                      "Se mesma placa, cartao esta na lista de "
                                      "veiculos. Caso contrario, existe na lista "
                                      "para outra placa que nao a solicitada. "
                                      "Acesso NEGADO!",
                                      Plate[0], Plate[1], Plate[2],
                                      (unsigned char)Plate[3], (unsigned char)Plate[4]);
                            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CONDUCTOR);
                            bValidAccess = false;
                        }
                    }
                } else if (m_pContext->GetRecognitionManager()->FindPlateByVehicleCard(
                               m_Card, ReturnPlate)) {

                    // Testar se leitora corrente está habilitada para o caso...
                    if (!IsEnabledReader(eReader, ReturnPlate.GetEnabledReaders())) {

                        DLOG_INFO("Leitora nao habilitada para esta validacao!\n");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_VEHICLE);
                        bValidAccess = false;
                        return valRes;
                    }

                    if (!strcmp(m_PlateBetweenCards.GetId(), ReturnPlate.GetId())) {

                        // Se cartão em espera era realmente veículo...
                        if (m_bWaitingForAnOfflineCard == CT_VEHICLE) {

                            char Plate[5];
                            memcpy(&Plate, ReturnPlate.GetId(), 5);
                            DLOG_INFO("Encontrado cartao do veiculo para placa "
                                      "%c%c%c%02x%02x. Acesso PERMITIDO!",
                                      Plate[0], Plate[1], Plate[2],
                                      (unsigned char)Plate[3], (unsigned char)Plate[4]);
                            valRes.GetEvent().SetId(CEvent::ACCESS_GRANTED_VEHICLE);
                            bValidAccess = true;
                        } else {

                            char Plate[5];
                            memcpy(&Plate, ReturnPlate.GetId(), 5);
                            DLOG_INFO("Cartao encontrado para placa %c%c%c%02x%02x. "
                                      "Se mesma placa, cartao esta na lista de "
                                      "condutores. Caso contrario, existe na lista "
                                      "para outra placa que nao a solicitada. "
                                      "Acesso NEGADO!",
                                      Plate[0], Plate[1], Plate[2],
                                      (unsigned char)Plate[3], (unsigned char)Plate[4]);
                            valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_VEHICLE);
                            bValidAccess = false;
                        }
                    }
                } else {

                    // Se NÃO houver relação entre os cartões...
                    if (valRes.GetEvent().GetId() ==
                        CEvent::ACCESS_DENIED_WAITING_CONDUCTOR) {

                        DLOG_INFO("Cartao de condutor nao existe na lista. Acesso "
                                  "NEGADO!");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_VEHICLE);

                    } else if (valRes.GetEvent().GetId() ==
                               CEvent::ACCESS_DENIED_WAITING_VEHICLE) {
                        DLOG_INFO("Cartao de veiculo nao existe na lista. Acesso "
                                  "NEGADO!");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CONDUCTOR);

                    } else {
                        // Para teste...
                        DLOG_INFO("Evento sem ID (Sem esperar condutor e sem "
                                  "esperar veiculo). Acesso NEGADO!");
                        valRes.GetEvent().SetId(CEvent::ACCESS_DENIED_CARDUSEID);
                    }
                    // Para ambos os casos, o acesso é negado...
                    bValidAccess = false;
                }

                // Independentemente de ocorrer a permissão, não há mais espera
                // por um segundo cartão...
                m_bWaitingForAnOfflineCard = CT_NONE;
            }

        } else { // Ocorreu uma validação de FACE...
            DLOG_WARNING("\n\n\nOcorreu uma validacao de FACE:\n");
            DLOG_WARNING("### NAO IMPLEMENTADO AINDA! ###\n\n\n");
        }

        bValidAccess = false;
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
    /////////////////////////////CHECA FILIAL
    /// ESTRANGEIRA???///////////////////////////////////////
    // bool checkForeignSubsidiary =
    /////////////////////////////CHECA
    /// BDCC???///////////////////////////////////////
    //	if
    //(m_pContext->GetConfiguration()->GetReaderConfig(eReader).GetBdccPersonTypeValidation(m_CardType
    //- 1)) {
    //
    //		PrepareSmartCard(); //**** Já usado em Internal_ValidateCard
    //
    //		if (!BdccValidation.CheckBdccCriptoData(m_pContext,
    // m_pSmartCardHandler, m_Card)) {
    //			throw CEventException(CEvent::ACCESS_DENIED_BDCC,
    // m_pSmartCardHandler->GetCard());
    //		}
    //	}

    // numero da matricula
    valRes.SetEnroll(m_Card);
    //	// Seta número lógico + número físico
    //	valRes.GetEvent().SetLogicalNumber(m_RecognitionNumber, m_Card);
    if (m_bPersonValidation) {
        valRes.GetEvent().SetPersonId(m_Card.GetPerson());
        DLOG_INFO("ID Facial: \"%s\"\n", m_Card.GetPerson());
    } else {

        char RecogID[5];
        memcpy(&RecogID, m_Card.GetPlate(), 5);
        DLOG_INFO("Plate: %c%c%c%02X%02X\n", RecogID[0], RecogID[1], RecogID[2],
                  (unsigned char)RecogID[3], (unsigned char)RecogID[4]);

        valRes.GetEvent().SetRecognitionId(m_Card.GetPlate());
    }

    // tipo da pessoa
    valRes.SetCardType(m_CardType);
    // Leitora
    valRes.GetEvent().SetReader(m_eReader);

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

void CRecognitionValidation::internal_ValidateCard()
{
    // recolhe os dados necessarios na validacao
    CBuffer ValRequest;
    PrepareData(ValRequest);
    // faz o pedido de validacao ao driver
    if (m_bPersonValidation) {
        m_pContext->GetOutputSocket()->RequestSizedData(RequestPersonValidation,
                                                        ValRequest, m_Buffer);
    } else {
        m_pContext->GetOutputSocket()->RequestSizedData(RequestDocumentValidation,
                                                        ValRequest, m_Buffer);
    }
}

void CRecognitionValidation::PrepareData(CBuffer &dest)
{

    if (m_bPersonValidation) {
        DLOG_INFO("\n Requisicao de Pessoa: Facial \n");
        dest.PutBytes(m_Card.GetPerson(), PERSONID_SIZE);
    } else {
        DLOG_INFO("\n Requisicao de Acesso com Documento: LPR \n");

        dest.PutByte((BYTE)DT_Plate); // Tipo do documento (LPR/Placa)...
        // Insere tamanho no datagrama...
        dest.PutWord((WORD)DT_Plate);
        // Insere identificador...
        dest.PutBytes(m_Card.GetPlate(), 5);
    }

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

void CRecognitionValidation::ParseValidationData(CValidationResult &valRes,
                                                 CBuffer &buffer)
{

    // campo: "Ignorar resposta sobre permissão de acesso e validar pela lista?
    // 0 - não, 1 - sim";
    m_bOnlineCheckList = (buffer.GetByte() == 1) ? true : false;
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
    if (m_bOnlineCheckList) {
        eventId = (CEvent::EventCode)CAccessEvent::ACCESS_DENIED_VEHICLE;
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

    if (!m_bPersonValidation) {
        m_CardType = buffer.GetByte();
        m_CardTechnology = buffer.GetByte();
    }

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
    // Estrutura do Evento
    switch (eventId) {
    case 0:
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
        buffer.GetBytes(temp, 11); //
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
    case CEvent::ACCESS_GRANTED_VEHICLE:
    case CEvent::ACCESS_DENIED_VEHICLE:
    case CEvent::ACCESS_DENIED_CROWDED: {
        // NIvel atual da pessoa
        valRes.SetOriginalLevel(buffer.GetByte());
        // Faixa horaria que o crédito será decrementada
        valRes.GetEvent().SetAccessCredits(buffer.GetByte());
        // Nivel de conferencia biometrico
        valRes.SetConferenceLevel(buffer.GetByte());
        // Revista
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

BYTE CRecognitionValidation::CalcNextLevel(BYTE nOriginalLevel)
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

void CRecognitionValidation::DefaultValidation(bool bOnLineValidation,
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
    if (pReaderConfig->CheckList() || !bOnLineValidation || m_bOnlineCheckList) {
        if (!m_pContext->GetAuthorizedCardList()->LogicalIDContains(
                m_RecognitionNumber, m_eReader, CardType)) {
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

    if (!bOnLineValidation || m_bOnlineCheckList) {
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

bool CRecognitionValidation::IsTimeOutLPR(WORD timeOut)
{
    if (CFirmwareUtil::GetTickCount() > (m_TimeOutLPR + timeOut)) {
        return true;
    }
    return false;
}

bool CRecognitionValidation::IsEnabledReader(EReader Reader, UINT EnabledReaders)
{
    return (EnabledReaders & (1 << Reader)) > 0;
}
} // namespace seguranca

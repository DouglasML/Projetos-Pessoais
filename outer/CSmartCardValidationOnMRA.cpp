#include "CSmartCardValidationOnMRA.h"
#include "CActionManager.h"
#include "CAuthenticationException.h"
#include "CAuthorizedCardList.h"
#include "CBiometricManager.h"
#include "CContext.h"
#include "CDevice.h"
#include "CEventException.h"
#include "CEventManager.h"
#include "CFirmwareUtil.h"
#include "CHolidayList.h"
#include "CMCAHelper.h"
#include "CMraManager.h"
#include "CMraManagerImpl.h"
#include "COutputSocket.h"
#include "CPasswordManager.h"
#include "CPermissionManager.h"
#include "CPersonManager.h"
#include "CProcessSmartCard.h"
#include "CRefectoryControl.h"
#include "CRefectoryControlManager.h"
#include "CSmartCardHandler.h"
#include "CSmartCardUpdates.h"
#include "CStateTable.h"
#include "CValidationException.h"
#include "dlog.h"

#include "unistd.h"

using digicon::CAuthenticationException;
using digicon::CCardReader;
using digicon::CMCA;
using digicon::CTurnstile;
using digicon::CValidationException;
using seguranca::CBiometricManager;
using seguranca::CMraManager;
using seguranca::CRefectoryControl;
using seguranca::CRefectoryControlManager;

namespace seguranca
{

CSmartCardValidationOnMRA::CSmartCardValidationOnMRA()
    :                                        //
      m_pContext(NULL),                      //
      m_pSmartCardHandler(NULL),             //
      m_Now(0),                              //
      m_eReader(NO_CNFG_READER),             //
      m_PendingDays(0),                      //
      m_CardFlags(0),                        //
      m_bCheckHourlyRangeTimeKeeping(false), //
      m_bCheckHourlyRangeAccess(false),      //
      m_UpdateListDate(0),                   //
      m_PeopleKindSit(0),                    //
      m_InterJourney(0),                     //
      m_CreditControlType(None),             //
      m_AccessCredits(0),                    //
      m_Messages(0),                         //
      m_bLevelChanged(false),                //
      m_OriginalLevel(EMPTY_LEVEL),          //
      m_NewLevel(EMPTY_LEVEL),               //
      m_LevelDir(LD_Undefined),              //
      m_CardConferenceLevel(0),              //
      m_BioUser(0),                          //
      m_AccessDir(CAccessEvent::AD_None),    //
      fBackupList(NULL),                     //
      fBKPLastAccess(0),                     //
      fBKPLastUpdate(0),                     //
      fBKPCreditRange(0),                    //
      fBKPCredits(0),                        //
      fBKPRefectoryAccess(0),                //
      fBKPMessages(0),                       //
      fBKPLunchStartDate(0)                  //
{
    m_pSmartCardHandler = new CSmartCardHandler();
    memset(m_FieldInUse, 0, sizeof(m_FieldInUse));
    memset(m_cMessage, 0, sizeof(m_cMessage));
    memset(m_pPassword, ' ', sizeof(m_pPassword));
}

CSmartCardValidationOnMRA::~CSmartCardValidationOnMRA()
{
    SAFE_DELETE(m_pSmartCardHandler);
}

CValidationResult CSmartCardValidationOnMRA::ValidateCard(const digicon::CCard Card,
                                                          EReader eReader,
                                                          BYTE nKeyPressed,
                                                          CContext *pContext)
{
    // passa o context para a variavel membro
    // que sera usada em todo o processo de validacao
    m_pContext = pContext;
    m_eReader = eReader;
    m_LevelDir = LD_Undefined;

    // variaveis utilizadas
    CDevice *pFirmConfig = pContext->GetConfiguration();
    CFirmwareProperties *pFirmProps = &pContext->GetConfiguration()->GetProperties();
    CReaderConfig *pReaderConfig =
        &pContext->GetConfiguration()->GetReaderConfig(eReader);
    CActionManager *pActionMgr = pContext->GetActionManager();

    // Pra pegar a leitora de cartao, o identificador eh o mesmo que o da
    // configuracao.
    CMCA::EMRAReader eMraReader = (CMCA::EMRAReader)((CMCA::ECardReader)(eReader - 16));
    CMRAReader *pMRAReader = pContext->GetMCA()->GetMRAReader(eMraReader);

    DBG_MRA("Foi inicializada? : %d\n", pMRAReader->IsInitialized());
    DBG_MRA("Validando SmartCard lido no MRA %d\n", (CMCA::EMRAReader)eMraReader);
    // Verifica se existe mapa do smartcard
    if (pContext->GetConfiguration()->GetSmartCardMap().IsEmpty()) {
        if (pReaderConfig->UseDisplay()) {
            CAction action;
            action.GetDisplay().SetAction(1);
            action.GetDisplay().SetTime(2000);
            CDisplay::DisplayText theText;
            memcpy(theText.line1, "    CARREGAR    ", 16);
            memcpy(theText.line2, " MAPA DO CARTAO ", 16);
            action.SetDisplayMsg(&theText);
            pActionMgr->QueueActions(action);
        }
        throw CException("smart card map is empty");
    }
    /*
     * Inicialização de variaveis utilizadas na validacao do acesso
     */
    time_t GMTZeroTime = CFirmwareUtil::GetDateTime();
    m_Now = CFirmwareUtil::GMTToLocalDateTime(GMTZeroTime, *pFirmProps);
    m_PendingDays = pFirmConfig->GetPendingDays();
    m_CardFlags = 0;
    m_bCheckHourlyRangeTimeKeeping = false;
    m_bCheckHourlyRangeAccess = false;
    m_OriginalLevel = EMPTY_LEVEL;
    m_NewLevel = EMPTY_LEVEL;
    m_bLevelChanged = false;
    m_CreditControlType = None;
    m_CardConferenceLevel = 0;
    m_BioUser.Clear();
    m_Messages = 0;
    m_PeopleKindSit = 0;
    memset(m_cMessage, 0, sizeof(m_cMessage));
    m_Card = Card;

    CValidationResult ValResult;

    while (TRUE) {
        try {
            // Limpa os buffers e associa um novo identificador
            m_pSmartCardHandler->Reset(Card, &pFirmConfig->GetSmartCardMap(),
                                       (CMRAReader *)pMRAReader);
            // Pode formatar o cartao
            m_pSmartCardHandler->SetCanFormat(true);
            // Faz a validacao do cartao
            /*TODO: MRA: Validar o SmartCard lido no MRA*/
            //			ValResult = InternalValidateCard(m_pSmartCardHandler,
            // eReader, nKeyPressed, pContext);
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
            CMCAHelper::TimedDisplay(1000, "Erro na leitura ", "                ",
                                     pContext);
            continue;
        } catch (CEventException &ex) {
            DLOG_INFO("Acesso Negado: %s\n", ex.GetMessage());
            ValResult.SetOriginalLevel(m_OriginalLevel);
            // Mantem o novo nivel como o original, pois deu acesso negado
            ValResult.SetNewLevel(m_OriginalLevel);
            ValResult.SetEvent(ex.GetEvent());
            ValResult.GetEvent().SetLevel(m_OriginalLevel);
            ValResult.GetEvent().SetReader(m_eReader);
        } catch (CValidationException &ex) {
            ex.Raise();
        } catch (CException &ex) {
            DLOG_WARNING("Erro generico na validacao do acesso\n");
            if (pReaderConfig->UseDisplay() && !pActionMgr->IsUsingDisplay()) {
                CMCAHelper::TimedDisplay(1200, "Acesso negado   ", "Erro generico   ",
                                         m_pContext);
            }
            ex.Raise();
        }
        break;
    } // while

    // numero da matricula
    ValResult.SetEnroll(m_Enroll);

    // tipo da pessoa
    int iCardType = m_PeopleKindSit & 0x0F;
    ValResult.SetCardType(iCardType);

    // revista aleatória
    if (pReaderConfig->CheckFriskRanges(m_Now)) {
        BYTE friskPercent = pReaderConfig->GetFriskPercent(iCardType - 1);
        if (friskPercent) {
            ValResult.SetFrisk(FRISK_RANDOM);
        }
    }

    // backup dos dados originais
    ValResult.SetLastAccess(fBKPLastAccess);
    ValResult.SetLastUpdate(fBKPLastUpdate);
    ValResult.SetCreditRange(fBKPCreditRange);
    ValResult.SetCredits(fBKPCredits);
    ValResult.SetRefectoryAccess(fBKPRefectoryAccess);
    ValResult.SetMsgCount(fBKPMessages);
    ValResult.SetLunchControlStartDate(fBKPLunchStartDate);

    try {
        // Salva as modificacoes no cartao
        m_pContext->GetProcessSmartCard()->SaveModifiedData(m_pSmartCardHandler);
    } catch (CException &ex) {
        DLOG_WARNING("Erro na atualizando cartao: %s\n", ex.GetMessage());
        if (pReaderConfig->UseDisplay() && !pActionMgr->IsUsingDisplay())
            CMCAHelper::TimedDisplay(1000, "Erro na gravacao", "                ",
                                     pContext);
        ex.Raise();
    }
    return ValResult;
}

CValidationResult
CSmartCardValidationOnMRA::InternalValidateCard(CSmartCardHandler *pSmartCardHandler,
                                                EReader eReader, BYTE nKeyPressed,
                                                CContext *pContext)
{
    DBG_MRA("Passei por aqui\n");

    usleep(1500000);
    // variaveis utilizadas
    CDevice *pConfig = pContext->GetConfiguration();
    CFirmwareProperties *pFirmProps = &pConfig->GetProperties();
    const CSmartCardMap *pSmartCardMap = &pConfig->GetSmartCardMap();
    DBG_MRA("Passei por aqui 0\n");
    CReaderConfig *pReaderConfig = &pConfig->GetReaderConfig(eReader);

    // Le a lista de todos os campos que podem ser usados na validacao do acesso
    pSmartCardMap->GetFieldInAccessValidation(m_FieldInUse);
    pSmartCardHandler->SetUsedFieldList(m_FieldInUse);

    DBG_MRA("Passei por aqui 1\n");
    CAccessEvent ResultEvent(CEvent::ACCESS_GRANTED, pSmartCardHandler->GetCard());
    ResultEvent.SetReader(eReader);

    DBG_MRA("Passei por aqui 2\n");
    int m_iPersonType = m_PeopleKindSit & 0x0F;
    if (pReaderConfig->GetBdccPersonTypeValidation(m_iPersonType - 1) == 1) {
        if (!BdccValidation.CheckBdccCriptoData(m_pContext, pSmartCardHandler, m_Card)) {
            throw CEventException(CEvent::ACCESS_DENIED_BDCC,
                                  pSmartCardHandler->GetCard());
        }
    }

    DBG_MRA("Passei por aqui 3\n");

    // Data da ultima passagem
    if (!CheckLastPassDate(pSmartCardHandler)) {
        throw CEventException(CEvent::ACCESS_DENIED_OUTDATED_CARD,
                              pSmartCardHandler->GetCard());
    }

    DBG_MRA("Passei por aqui 4\n");
    // Le os flags do smartcard
    ReadCardFlags(pSmartCardHandler, pReaderConfig);
    DefineInUseFields(pReaderConfig);

    DBG_MRA("Passei por aqui 5\n");
    if (fBackupList) {
        if (fBackupList->FindCard(pSmartCardHandler->GetCard().GetId())) {
            CValCtx valCtx = fBackupList->getLastSearch();

            // le a data de ultimo acesso
            time_t lastAccess = 0;
            int accFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
                pSmartCardHandler, CSmartCardMap::LastPassDate, &lastAccess);

            // le a data de ultima atualizacao
            time_t lastUpdate = 0;
            int upFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
                pSmartCardHandler, CSmartCardMap::LastOnLineUpdateID, &lastUpdate);

            // imprime as datas no console
            char data1[STRDATETIMELEN];
            CFirmwareUtil::GetDateTimeString(valCtx.getDate(), data1, STRDATETIMELEN);
            char data2[STRDATETIMELEN];
            CFirmwareUtil::GetDateTimeString(lastAccess, data2, STRDATETIMELEN);
            char data3[STRDATETIMELEN];
            CFirmwareUtil::GetDateTimeString(valCtx.getLastUpdate(), data3,
                                             STRDATETIMELEN);
            DLOG_INFO("\nENCONTROU BACKUP DO CARTAO\n"
                      "Backup:      %s\n"
                      "Acesso:      %s\n"
                      "Atualizacao: %s\n\n",
                      data1, data2, data3);

            if (accFieldSize < 4) {
                DLOG_INFO("CAMPO DE ULTIMO ACESSO SEM PRECISAO SUFICIENTE PARA "
                          "RESTAURAR BACKUP\n");
            } else if (upFieldSize < 4) {
                DLOG_INFO("CAMPO DE ULTIMA ATUALIZACAO SEM PRECISAO SUFICIENTE "
                          "PARA RESTAURAR BACKUP\n");
            } else if (valCtx.getDate() != lastAccess) {
                DLOG_INFO("Ultimo acesso diferente, backup descartado\n");
            } else if (valCtx.getLastUpdate() != lastUpdate) {
                DLOG_INFO("Ultima atualizacao diferente, backup descartado\n");
            } else {
                // Se a data de ultimo acesso e a data de ultima atualizacao
                // forem
                // iguais ao do cartao, entao utiliza os dados do backup.
                CFirmwareUtil::GetDateTimeString(valCtx.getLastAccess(), data1,
                                                 STRDATETIMELEN);
                CFirmwareUtil::GetDateTimeString(valCtx.getRefectoryAccess(), data2,
                                                 STRDATETIMELEN);
                CFirmwareUtil::GetDateTimeString(valCtx.getLunchControlStartDate(), data3,
                                                 STRDATETIMELEN);
                DLOG_INFO("\nCard: %lld\n"
                          "Last access: %s\n"
                          "Level: %d\n"
                          "Credit Range: %d  Count: %d  Refectory Access: %s\n"
                          "Messages: %d\n"
                          "Lunch date: %s\n\n",
                          valCtx.getCardId(), data1, valCtx.getLevel(),
                          valCtx.getCreditRange(), valCtx.getCredits(), data2,
                          valCtx.getMessage(), data3);

                // RESTAURAR OS DADOS

                // data de ultimo acesso
                fBKPLastAccess = valCtx.getLastAccess();
                m_pContext->GetProcessSmartCard()->SetDateTimeField(
                    pSmartCardHandler, CSmartCardMap::LastPassDate, fBKPLastAccess);

                // nivel
                m_OriginalLevel = m_NewLevel = valCtx.getLevel();

                // creditos de acesso
                fBKPCreditRange = valCtx.getCreditRange();
                fBKPCredits = valCtx.getCredits();
                if (fBKPCreditRange) {
                    CSmartCardMap::FieldCode CreditRangeField =
                        (CSmartCardMap::FieldCode)(CSmartCardMap::RefectoryCreditRange1 +
                                                   fBKPCreditRange - 1);
                    m_pSmartCardHandler->SetFieldValue(CreditRangeField, &fBKPCredits, 1);
                }

                // data de ultima passagem pelo refeitorio
                fBKPRefectoryAccess = valCtx.getRefectoryAccess();
                m_pContext->GetProcessSmartCard()->SetDateTimeField(
                    pSmartCardHandler, CSmartCardMap::LastRefectoryPassDateTime,
                    fBKPRefectoryAccess);

                // quantidade de mensagens
                fBKPMessages = valCtx.getMessage();
                pSmartCardHandler->SetFieldValue(CSmartCardMap::MessageExhibitionCounter,
                                                 &fBKPMessages, 1);

                // data de acesso ao refeitorio
                fBKPLunchStartDate = valCtx.getLunchControlStartDate();
                m_pContext->GetProcessSmartCard()->SetDateTimeField(
                    pSmartCardHandler, CSmartCardMap::LunchControlStartDate,
                    fBKPLunchStartDate);
            }
        } else {
            DLOG_INFO("NAO ENCONTROU BACKUP DO CARTAO \"%lld\"\n",
                      pSmartCardHandler->GetCard().GetId());
        }
    }

    // Situacao
    if (pReaderConfig->CheckSituation()) {
        if (!CheckSituation(pSmartCardHandler)) {
            throw CEventException(CEvent::ACCESS_DENIED_SITUATION,
                                  pSmartCardHandler->GetCard());
        }
    }

    // Validade
    if (CHECK_VALIDITY(m_CardFlags) && pReaderConfig->CheckValidity()) {
        if (!CheckValidity(pSmartCardHandler, &ResultEvent)) {
            ResultEvent.SetId(CEvent::ACCESS_DENIED_VALIDITY);
            throw CEventException(ResultEvent);
        }
    }

    // Cartao mestre
    if (IsMasterCard()) {
        ResultEvent.SetId(CEvent::ACCESS_MASTER_CARD);
        CValidationResult ValResult;
        ValResult.SetEvent(ResultEvent);
        return ValResult;
    }

    // Bloqueio por falta
    if (pReaderConfig->CheckFaultBlocked()) {
        if (BLOCK_BY_FAULT(m_CardFlags)) {
            char cMsg[120];
            sprintf(cMsg, "Acesso negado por falta\n");
            throw CEventException(CEvent::ACCESS_DENIED_FAULT,
                                  pSmartCardHandler->GetCard(), cMsg);
        }
    }

    // Permissao de acesso
    WORD permissionID = 0;
    DLOG_INFO("CHECK PERMISSION(person: %s, reader: %s)\n",
              CHECK_ACCESS_RIGHTS(m_CardFlags) ? "yes" : "no",
              pReaderConfig->CheckPermission() ? "yes" : "no");
    if (CHECK_ACCESS_RIGHTS(m_CardFlags) && pReaderConfig->CheckPermission()) {
        if (!CheckPermission(pSmartCardHandler, eReader, &permissionID)) {
            char cMsg[120];
            sprintf(cMsg, "Acesso negado por local nao permitido. Permissao %d",
                    permissionID);
            throw CEventException(CEvent::ACCESS_DENIED_LOCAL,
                                  pSmartCardHandler->GetCard(), cMsg);
        }
    }

    // Faixa horária da permissao
    if (CHECK_ACCESS_RIGHTS(m_CardFlags) && pReaderConfig->CheckPermission() &&
        pReaderConfig->CheckPermissionSchedule()) {
        if (!CheckPermissionHourlyRange(pSmartCardHandler, eReader, permissionID)) {
            throw CEventException(CEvent::ACCESS_DENIED_PERMISSION_HOURLYRANGE,
                                  pSmartCardHandler->GetCard());
        }
    }

    // Nivel , Função 2 - ignora nível / função tem flag para ignorar nível
    if (CHECK_ANTI_PASSBACK(m_CardFlags) && pReaderConfig->CheckLevel() &&
        (pConfig->GetFunction(nKeyPressed) != 2 &&
         pConfig->GetFunctionIgnoreLevel(nKeyPressed) == false)) {
        if (!CheckLevel(pSmartCardHandler, &ResultEvent, pFirmProps, pReaderConfig)) {
            ResultEvent.SetId(CEvent::ACCESS_DENIED_LEVEL);
            throw CEventException(ResultEvent);
        }
    }

    // Anti-dupla , Função 2 - ignora anti-dupla
    if (CHECK_ANTI_PASSBACK(m_CardFlags) && pReaderConfig->CheckAntiPassBack() &&
        (pConfig->GetFunction(nKeyPressed) != 2 &&
         pConfig->GetFunctionIgnoreLevel(nKeyPressed) == false)) {
        if (!CheckAntiPassBack(pSmartCardHandler, &ResultEvent, pFirmProps,
                               pReaderConfig)) {
            ResultEvent.SetId(CEvent::ACCESS_DENIED_ANTIPASSBACK);
            throw CEventException(ResultEvent);
        }
    }

    // Afastamento
    if (CHECK_REMOVAL(m_CardFlags) && pReaderConfig->CheckRemoval()) {
        if (!CheckRemoval(pSmartCardHandler, &ResultEvent)) {
            ResultEvent.SetId(CEvent::ACCESS_DENIED_REMOVAL);
            throw CEventException(ResultEvent);
        }
    }

    // Faixa horária da pessoa
    if (pReaderConfig->CheckPersonSchedule() &&
        (m_bCheckHourlyRangeAccess || m_bCheckHourlyRangeTimeKeeping)) {
        if (!CheckPersonHourlyRange(pSmartCardHandler, pReaderConfig)) {
            throw CEventException(CEvent::ACCESS_DENIED_PERSON_HOURLYRANGE,
                                  pSmartCardHandler->GetCard());
        }
    }

    // Controle do intervalo de almoco (somente com controle de nivel, pois
    // precisa saber a direcao do acesso)
    if (pReaderConfig->CheckLevel()) {
        // Descobrir qual a direcao do acesso (entrada ou saida)
        m_AccessDir = pFirmProps->GetAccessDirection(eReader, m_LevelDir == LD_N1ToN2);
        if (pReaderConfig->CheckLunchInterval()      // leitora valida ?
            && CHECK_LUNCH_INTERVAL(m_CardFlags)     // pessoa valida ?
            && m_AccessDir == CAccessEvent::AD_In) { // direcao entrada ?
            if (!CheckLunchInterval(pSmartCardHandler, eReader)) {
                char cMsg[120];
                sprintf(cMsg, "Acesso negado em intervalo de almoco");
                throw CEventException(CEvent::ACCESS_DENIED_LUNCH_INTERVAL,
                                      pSmartCardHandler->GetCard(), cMsg);
            }
        }
    }

    // Controle do interjornada de trabalaho(somente com controle de nivel, pois
    // precisa saber a direcao do acesso)
    if (pReaderConfig->CheckLevel()) {
        // Descobrir qual a direcao do acesso (entrada ou saida)
        CAccessEvent::AccessDirection AccessDir =
            pFirmProps->GetAccessDirection(eReader, m_LevelDir == LD_N1ToN2);
        if (pReaderConfig->CheckInterJourney() && CHECK_INTER_JOURNEY(m_InterJourney) &&
            AccessDir == CAccessEvent::AD_In &&
            (m_pContext->GetConfiguration()->GetInterJourneyTime() > 0)) {
            if (!CheckInterJourney(pSmartCardHandler, eReader)) {
                char cMsg[120];
                sprintf(cMsg, "Acesso negado interjornada de trabalho");
                throw CEventException(CEvent::ACCESS_DENIED_INTERJOURNEY,
                                      pSmartCardHandler->GetCard(), cMsg);
            }
        }
    }

    // Tempo mínimo de permanência
    if (CHECK_MIN_STAYTIME(m_CardFlags)) {
        // Descobrir qual a direcao do acesso (entrada ou saida)
        if (m_AccessDir == CAccessEvent::AD_Out) {
            WORD PersonType = 0;
            // Alterado por conta do Caso 6725 - PersonType = GET_PERSON_TYPE(
            // m_PeopleKindSit );
            PersonType = m_PeopleKindSit & 0x0F;
            const BYTE minTime = pReaderConfig->GetMinimumStayTime(PersonType - 1);
            if (minTime) {
                if (!CheckMinimumStayTime(pSmartCardHandler, eReader, minTime)) {
                    char cMsg[120];
                    sprintf(cMsg, "Acesso negado pelo tempo minimo de permanencia");
                    throw CEventException(CEvent::ACCESS_DENIED_MIN_TIME,
                                          pSmartCardHandler->GetCard(), cMsg);
                }
            }
        }
    }

    //...................................................................................//
    // Tipo de pessoa
    //...................................................................................//
    if (pReaderConfig->CheckLevel() && pFirmProps->IsReaderBothDirections(eReader) &&
        m_LevelDir == LD_N2ToN1) {
        if (!CheckPersonType(pSmartCardHandler, pReaderConfig->GetPersonsAllowOut())) {
            throw CEventException(CEvent::ACCESS_DENIED_PERSON_TYPE_EXIT,
                                  pSmartCardHandler->GetCard());
        }
    } else {
        // apenas valida com o que tem em PersonTypes1
        if (!CheckPersonType(pSmartCardHandler, pReaderConfig->GetPersonsAllowIn())) {
            throw CEventException(CEvent::ACCESS_DENIED_PERSON_TYPE,
                                  pSmartCardHandler->GetCard());
        }
    }

    // Credito de acesso
    short AccessCreditRange = -1;
    if (m_CreditControlType > 0 &&
        pReaderConfig->GetCreditControl() != CReaderConfig::CC_NOCONTROL) {
        bool bDirCheck = true;
        // com nivel, verifica a direcao do acesso
        if (CHECK_ANTI_PASSBACK(m_CardFlags) && pReaderConfig->CheckLevel()) {
            // Descobrir qual a direcao do acesso (entrada ou saida)
            CAccessEvent::AccessDirection AccessDir =
                pFirmProps->GetAccessDirection(eReader, m_LevelDir == LD_N1ToN2);
            const CReaderConfig::ECreditControl eCredCntrl =
                (CReaderConfig::ECreditControl)(AccessDir == CAccessEvent::AD_In)
                    ? CReaderConfig::CC_ENTRANCE
                    : CReaderConfig::CC_EXIT;
            // verifica credito na direcao atual ?
            bDirCheck = (eCredCntrl & pReaderConfig->GetCreditControl()) > 0;
        }

        short response = CheckCredit(pSmartCardHandler, &AccessCreditRange);

        if (bDirCheck && response < 0) {
            // só consome se for tipo de reserva automática
            if (m_CreditControlType == Automatic_Lunch) {
                if (!LunchCreditControl(pSmartCardHandler, eReader,
                                        1)) // consome faixa reservada
                {
                    throw CEventException(CEvent::ACCESS_DENIED_CREDIT,
                                          pSmartCardHandler->GetCard());
                }
            } else {
                if (response == -1) {
                    // Negado credito
                    throw CEventException(CEvent::ACCESS_DENIED_CREDIT,
                                          pSmartCardHandler->GetCard());
                } else if (response == -2) {
                    // Negado fora da faixa
                    throw CEventException(CEvent::ACCESS_DENIED_CREDIT_RANGE,
                                          pSmartCardHandler->GetCard());
                }
            }
        }
    }

    // Lista de validação cartões autorizados/bloqueados
    if (pReaderConfig->CheckList()) {
        // Byte para verificar qual é o tipo do cartao da lista
        BYTE CardType = CReaderConfig::NONE;

        if (!pContext->GetAuthorizedCardList()->Contains(pSmartCardHandler->GetCard(),
                                                         eReader, CardType)) {
            // MMF - Include Reader for those events 10/02/2016
            ResultEvent.SetReader(eReader);
            if (pContext->GetAuthorizedCardList()->CardListType() ==
                CAuthorizedCardList::authorizedList) {
                throw CEventException(CEvent::ACCESS_DENIED_WHITE_LIST,
                                      pSmartCardHandler->GetCard());
            } else {
                throw CEventException(CEvent::ACCESS_DENIED_BLACK_LIST,
                                      pSmartCardHandler->GetCard());
            }
        }

        // caso nao seja um acesso negado, verifica se foi uma validacao do
        // cartao mestre
        if (GET_PERSON_TYPE(CardType) == CReaderConfig::MASTER_CARD) {
            ResultEvent.SetId(CEvent::ACCESS_MASTER_CARD);
        }
    }

    // Reserva Automática de almoço e Reserva/Cancela através de função
    CAccessEvent::AccessDirection AccessDir =
        pFirmProps->GetAccessDirection(eReader, m_LevelDir == LD_N1ToN2);
    if ((m_CreditControlType == Automatic_Lunch && AccessDir == CAccessEvent::AD_In) ||
        (pConfig->GetFunction(nKeyPressed) == 4 ||
         pConfig->GetFunction(nKeyPressed) == 5)) {
        if ((pReaderConfig->GetReaderType() == CReaderConfig::Ponto ||
             pReaderConfig->GetReaderType() == CReaderConfig::AcessoPonto) &&
            pReaderConfig->GetCreditControl() == CReaderConfig::CC_NOCONTROL) {
            const BYTE bOperation = pConfig->GetFunction(nKeyPressed);
            if (!LunchCreditControl(pSmartCardHandler, eReader, bOperation)) {
                if (bOperation == 4 || bOperation == 5) {
                    CDisplay::DisplayText Message = {};
                    memcpy(Message.line1, "Operacao nao    ", 16);
                    memcpy(Message.line2, "realizada       ", 16);
                    throw CValidationException(0, Message);
                }
            }
        }
    }

    CValidationResult ValResult;

    // TODO: PODE DAR PROBLEMA QUANDO FOR COFRE COLETOR
    // Biometria
    if (pReaderConfig->CheckBiometry() && m_CardConferenceLevel != 0) {
        if (!m_pContext->GetProcessSmartCard()->ReadTemplates(pSmartCardHandler,
                                                              m_eReader, m_BioUser)) {
            DLOG_INFO("Template biometrica nao encontrada no cartao\n");
            DLOG_INFO("Procurando Id da pessoa pelo cartao\n");
            CPerson person;
            if (m_pContext->GetPersonManager()->FindPersonByCard(m_Card, person)) {
                ValResult.SetPersonId(person.GetId());
                ValResult.SetConferenceLevel(person.GetConferenceLevel());
            } else {
                throw CEventException(CEvent::ACCESS_DENIED_WITHOUT_BIOMETRIC_TEMPLATE,
                                      pSmartCardHandler->GetCard());
            }
        }
    }

    // Mensagem do usuario
    // Somente se usar display, e nao houver funcao ativada
    if (pReaderConfig->UseDisplay() && nKeyPressed == 255) {
        CheckMessages(pSmartCardHandler);
    }

    // Senha
    if (pReaderConfig->CheckPassword()) {
        if (!ReadPassword(pSmartCardHandler)) {
            DLOG_INFO("Nao valida com senha\n");
        }
    }

    UpdateSmartCard(pSmartCardHandler, &ResultEvent, AccessCreditRange, pReaderConfig);

    ValResult.SetEvent(ResultEvent);
    ValResult.SetConferenceLevel(m_CardConferenceLevel);
    ValResult.SetBiometricData(m_BioUser);
    ValResult.SetPassword(m_pPassword);

    if (CHECK_ANTI_PASSBACK(m_CardFlags)) {
        ValResult.SetOriginalLevel(m_OriginalLevel);
        ValResult.SetNewLevel(m_NewLevel);
        ValResult.GetEvent().SetLevel(m_NewLevel);
    } else {
        DLOG_INFO("Nivel do cartao resetado, pois cartao nao valida "
                  "nivel/antidupla\n");
        ValResult.SetOriginalLevel(EMPTY_LEVEL);
        ValResult.SetNewLevel(EMPTY_LEVEL);
        ValResult.GetEvent().SetLevel(EMPTY_LEVEL);
    }

    // mensagem do colaborador
    if (strlen(m_cMessage) > 0) {
        ValResult.SetCollaboratorMsg(m_cMessage);
    }

    return ValResult;
}

void CSmartCardValidationOnMRA::SetUseField(BYTE FieldId, BYTE bUse)
{
    m_FieldInUse[FieldId - 1] = bUse;
}

void CSmartCardValidationOnMRA::DefineInUseFields(const CReaderConfig *pCardReaderConfig)
{
    for (int i = 0; i < 7; i++) {
        SetUseField(CSmartCardMap::SundayTimeKeepingRange + i, 0);
        SetUseField(CSmartCardMap::SundayAccessRange + i, 0);
    }

    // Desativa os campos de permissao
    if (!CHECK_ACCESS_RIGHTS(m_CardFlags) || !pCardReaderConfig->CheckPermission()) {
        SetUseField(CSmartCardMap::NormalDaysPermission, 0);
        SetUseField(CSmartCardMap::HolidayPermission, 0);
        SetUseField(CSmartCardMap::SaturdayPermission, 0);
        SetUseField(CSmartCardMap::SundayPermission, 0);
    }

    // Validade
    if (!CHECK_VALIDITY(m_CardFlags) || !pCardReaderConfig->CheckValidity())
        SetUseField(CSmartCardMap::Validity, 0);

    // Nivel
    if (!pCardReaderConfig->CheckLevel() && !pCardReaderConfig->CheckAntiPassBack())
        SetUseField(CSmartCardMap::CardAccessLevel, 0);

    // Afastamento
    if (!CHECK_REMOVAL(m_CardFlags) || !pCardReaderConfig->CheckRemoval()) {
        SetUseField(CSmartCardMap::StartRemoval, 0);
        SetUseField(CSmartCardMap::EndRemoval, 0);
    }

    // Credito de acesso
    if (m_CreditControlType == None ||
        pCardReaderConfig->GetCreditControl() == CReaderConfig::CC_NOCONTROL) {
        SetUseField(CSmartCardMap::LastRefectoryPassDateTime, 0);
        for (int i = 0; i < 6; i++) {
            SetUseField(CSmartCardMap::RefectoryCreditRange1 + i, 0);
            SetUseField(CSmartCardMap::RefectoryRange1 + i, 0);
        }
    }
    // Reserva automática de almoço
    if (m_CreditControlType == Automatic_Lunch) {
        SetUseField(CSmartCardMap::RefectoryRange1, 1);
    }

    BYTE WeekDay = CFirmwareUtil::GetBrokedDateTime(m_Now).tm_wday;

    // Faixa horária
    if (pCardReaderConfig->CheckPersonSchedule() || m_bCheckHourlyRangeTimeKeeping)
        SetUseField(CSmartCardMap::SundayTimeKeepingRange + WeekDay, 1);

    if (pCardReaderConfig->CheckPermissionSchedule() || m_bCheckHourlyRangeAccess)
        SetUseField(CSmartCardMap::SundayAccessRange + WeekDay, 1);

    if (CHECK_LUNCH_INTERVAL(m_CardFlags) && (pCardReaderConfig->CheckLunchInterval() ||
                                              pCardReaderConfig->UpdateLunchInterval())) {
        SetUseField(CSmartCardMap::TempoIntervaloAlmoco, 1);
        SetUseField(CSmartCardMap::LunchControlStartDate, 1);
    }

    if (CHECK_INTER_JOURNEY(m_InterJourney) && pCardReaderConfig->CheckInterJourney() &&
        (m_pContext->GetConfiguration()->GetInterJourneyTime() > 0)) {
        SetUseField(CSmartCardMap::LunchControlStartDate, 1);
        SetUseField(CSmartCardMap::InterJourney, 1);
    }

    if (CHECK_MIN_STAYTIME(m_CardFlags)) {
        SetUseField(CSmartCardMap::MinimumStayTimeDateTime, 1);
    }

    // sempre le o numero da matricula do cartao
    SetUseField(CSmartCardMap::CardNumber, 1);
}

void CSmartCardValidationOnMRA::ReadCardFlags(CSmartCardHandler *pSmartCardHandler,
                                              const CReaderConfig *pCardReaderConfig)
{
    if (pSmartCardHandler->GetFieldValue(CSmartCardMap::CardStatus, &m_CardFlags, 1) !=
        1) {
        // TODO: deveria gerar uma excecao para nao permitir a validacao do
        // acesso, caso nao exista este campo.
        return;
    }
    if (pSmartCardHandler->GetFieldValue(CSmartCardMap::PeopleKindSituation,
                                         &m_PeopleKindSit, 1) != 1) {
        // TODO: deveria gerar uma excecao para nao permitir a validacao do
        // acesso, caso nao exista este campo.
        return;
    }

    // inicializa os dados de backup de credito
    // estes campos serao preenchidos somente se houver consumo
    fBKPCreditRange = 0;
    fBKPCredits = 0;

    // backup da data de ultimo acesso
    m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastPassDate, &fBKPLastAccess);
    // backup da data de ultima atualizacao online
    m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastOnLineUpdateID, &fBKPLastUpdate);
    // backup da data de ultima passagem pelo refeitorio
    m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastRefectoryPassDateTime,
        &fBKPRefectoryAccess);
    // backup da quantidade de mensagens
    pSmartCardHandler->GetFieldValue(CSmartCardMap::MessageExhibitionCounter,
                                     &fBKPMessages, 1);
    // backup da data de acesso ao refeitorio
    m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LunchControlStartDate, &fBKPLunchStartDate);

    if (pCardReaderConfig->CheckInterJourney()) {
        BYTE buffer[2];
        // Le o campo de interjornadas para controle
        const int fieldSize =
            pSmartCardHandler->GetFieldValue(CSmartCardMap::InterJourney, buffer, 2);
        if (fieldSize == 2) {
            CBuffer data(2);
            data.PutBytes(buffer, 2);
            data.Flip();
            m_InterJourney = data.GetWord();
        } else {
            m_InterJourney = 0;
            DLOG_WARNING("Campo Interjornada com tamanho %d incorreto no mapa\n",
                         fieldSize);
        }
    }

    // TODO: Se a leitora não controla permissao nem faixas não precisaria ler
    // estes campos do cartão
    BYTE ConsistenciaHoraria;
    if (pSmartCardHandler->GetFieldValue(CSmartCardMap::FxHorariaCredRef,
                                         &ConsistenciaHoraria, 1) != 1) {
        // TODO: deveria gerar uma excecao para nao permitir a validacao do
        // acesso, caso nao exista este campo.
        return;
    }
    // 4 primeiros bits
    m_bCheckHourlyRangeTimeKeeping =
        (ConsistenciaHoraria & 0xF) == 3 || (ConsistenciaHoraria & 0xF) == 1;
    m_bCheckHourlyRangeAccess =
        (ConsistenciaHoraria & 0xF) == 2 || (ConsistenciaHoraria & 0xF) == 1;
    // 4 ultimos bits
    m_CreditControlType = (CreditControlType)((ConsistenciaHoraria & 0xF0) >> 4);

    DLOG_INFO("Status Flags: 0x%X - Consist. Horaria: 0x%X\n", m_CardFlags,
              ConsistenciaHoraria);

    // numero de matricula
    m_pContext->GetProcessSmartCard()->GetEnroll(pSmartCardHandler, m_Enroll);

    // Nivel atual
    pSmartCardHandler->GetFieldValue(CSmartCardMap::CardAccessLevel, &m_OriginalLevel, 1);
    // Caso o nivel nao sofra alteracoes, mantem o original
    m_NewLevel = m_OriginalLevel;

    // nivel de conferencia biometrico
    pSmartCardHandler->GetFieldValue(CSmartCardMap::ConferenceLevel,
                                     &m_CardConferenceLevel, 1);
    DLOG_INFO("nivel de conferencia do cartao: %d\n", m_CardConferenceLevel);
}

void CSmartCardValidationOnMRA::UpdateSmartCard(CSmartCardHandler *pSmartCardHandler,
                                                CAccessEvent *pEvent,
                                                short AccessCreditRange,
                                                const CReaderConfig *pReaderConfig)
{
    pEvent->SetId(CEvent::ACCESS_GRANTED);

    // Atualizacao da quantidade de mensagens, a leitora tem q usar display
    if (m_Messages > 0 && strlen(m_cMessage) > 0) {
        m_Messages--;
        pSmartCardHandler->SetFieldValue(CSmartCardMap::MessageExhibitionCounter,
                                         &m_Messages, sizeof(m_Messages));
        pEvent->SetMessageUsedFlag(true);
    }

    // Atualizacao do nivel
    if (pReaderConfig->CheckLevel() || pReaderConfig->CheckAntiPassBack()) {
        if (m_bLevelChanged) {
            pSmartCardHandler->SetFieldValue(CSmartCardMap::CardAccessLevel, &m_NewLevel,
                                             1);
        }
    }

    // Atualizacao dos creditos de acesso
    if (AccessCreditRange >= 0 && AccessCreditRange <= 6 && m_CreditControlType != None) {
        if (m_CreditControlType == Control_Range ||
            m_CreditControlType == Control_Quota) {
            CSmartCardMap::FieldCode CreditRangeNumber = (CSmartCardMap::FieldCode)(
                CSmartCardMap::RefectoryCreditRange1 + AccessCreditRange);
            if (pSmartCardHandler->GetFieldValue(CreditRangeNumber, &m_AccessCredits,
                                                 1) == 1) {
                // guarda um backup das informacoes originais
                fBKPCreditRange = AccessCreditRange + 1;
                fBKPCredits = m_AccessCredits;
                // efetua o desconto do credito
                pSmartCardHandler->SetFieldValue(CreditRangeNumber, &--m_AccessCredits,
                                                 sizeof(m_AccessCredits));
            }
        }
        pEvent->SetAccessCredits(AccessCreditRange);
    } else {
        // Para evitar de mandar 0 quando não controlar créditos.
        pEvent->SetAccessCredits(0xFF);
    }

    // Atualizacao da data de controle do intervalo de almoco quando for saída
    // Atualização da data de controle da interjornada quando for saída
    if ((CHECK_LUNCH_INTERVAL(m_CardFlags) && pReaderConfig->UpdateLunchInterval()) ||
        (CHECK_INTER_JOURNEY(m_InterJourney) && pReaderConfig->CheckInterJourney() &&
         m_pContext->GetConfiguration()->GetInterJourneyTime() > 0)) {
        if (m_AccessDir == CAccessEvent::AD_Out) {
            const BYTE WeekDay = CFirmwareUtil::GetBrokedDateTime(m_Now).tm_wday;
            BYTE Range[21];
            time_t LunchIntervalStart = 0;
            if (ReadLunchIntervalInfo(pSmartCardHandler, Range, LunchIntervalStart)) {
                const time_t CurrentDate = CFirmwareUtil::GetTimeInSeconds(m_Now);
                // somente atualiza se a data atual e a de última passagem não
                // estão dentro do horário de almoço do dia
                if (IsInHourlyRange(CurrentDate / 60, Range + (WeekDay * 3))) {
                    time_t LastAccess = 0;
                    int DateFieldSize =
                        m_pContext->GetProcessSmartCard()->GetDateTimeField(
                            pSmartCardHandler, CSmartCardMap::LastPassDate, &LastAccess);
                    if (DateFieldSize == 3 || DateFieldSize == 4) {
                        const WORD CurrentDate = CFirmwareUtil::GetDateInDays(m_Now);
                        char cDateTime[STRDATETIMELEN];
                        DLOG_INFO("Ultimo acesso: %s \n",
                                  CFirmwareUtil::GetDateTimeString(LastAccess, cDateTime,
                                                                   STRDATETIMELEN));
                        const WORD LastAccessDate =
                            CFirmwareUtil::GetDateInDays(LastAccess);
                        if (CurrentDate ==
                            LastAccessDate) // Se mudou o dia jah esta liberado
                        {                   // Se for o mesmo dia verifica a hora
                            LastAccess = CFirmwareUtil::GetTimeInSeconds(LastAccess);
                            if (!IsInHourlyRange(LastAccess / 60,
                                                 Range + (WeekDay * 3))) {
                                m_pContext->GetProcessSmartCard()->SetDateTimeField(
                                    pSmartCardHandler,
                                    CSmartCardMap::LunchControlStartDate, m_Now);
                            }
                        } else {
                            m_pContext->GetProcessSmartCard()->SetDateTimeField(
                                pSmartCardHandler, CSmartCardMap::LunchControlStartDate,
                                m_Now);
                        }
                    }
                } else {
                    m_pContext->GetProcessSmartCard()->SetDateTimeField(
                        pSmartCardHandler, CSmartCardMap::LunchControlStartDate, m_Now);
                }
            }
        }
    }
    // Atualizacao da data da ultima passagem
    m_pContext->GetProcessSmartCard()->SetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastPassDate, m_Now);

    // Atualizacao da data de ultima passagem no refeitorio
    if (m_CreditControlType != None &&
        pReaderConfig->GetCreditControl() != CReaderConfig::CC_NOCONTROL) {
        m_pContext->GetProcessSmartCard()->SetDateTimeField(
            pSmartCardHandler, CSmartCardMap::LastRefectoryPassDateTime, m_Now);
    }

    // Se a pessoa e a leitora verificam tempo mínimo de permanência atualiza
    // data de controle
    if (CHECK_MIN_STAYTIME(m_CardFlags)) {
        WORD PersonType = 0;
        // Alterado por conta do Caso 6725 - PersonType = GET_PERSON_TYPE(
        // m_PeopleKindSit );
        PersonType = m_PeopleKindSit & 0x0F;
        const BYTE minTime = pReaderConfig->GetMinimumStayTime(PersonType - 1);
        if (minTime) {
            // Atualiza o campo somente na entrada
            if (m_AccessDir == CAccessEvent::AD_In) {
                m_pContext->GetProcessSmartCard()->SetDateTimeField(
                    pSmartCardHandler, CSmartCardMap::MinimumStayTimeDateTime, m_Now);
            }
        }
    }
}

bool CSmartCardValidationOnMRA::IsInHourlyRange(WORD Time, const BYTE *HourlyRange) const
{
    BYTE range[] =                                       //
        {(BYTE)(HourlyRange[1] >> 4), HourlyRange[0],    /*start  12 bits*/
         (BYTE)(HourlyRange[1] & 0x0F), HourlyRange[2]}; /*end    12 bits*/
    CBuffer buff(4);
    buff.PutBytes(range, 4);
    buff.Flip();
    WORD Start = buff.GetWord();
    WORD End = buff.GetWord();

    const bool bResult = (Start <= Time && Time <= End);
    if (bResult) {
        char cTime[STRTIMELEN], cStart[STRTIMELEN], cEnd[STRTIMELEN];
        DLOG_INFO("Hora: %s - (%s - %s) \n",
                  CFirmwareUtil::GetTimeString(Time, cTime, STRTIMELEN),
                  CFirmwareUtil::GetTimeString(Start, cStart, STRTIMELEN),
                  CFirmwareUtil::GetTimeString(End, cEnd, STRTIMELEN));
    }
    return bResult;
}

void CSmartCardValidationOnMRA::CheckMessages(CSmartCardHandler *pSmartCardHandler)
{
    m_Messages = 0;
    bool bShowMessage = false;

    // verifica o 999999
    BYTE DateTimeBytes[6] = {};
    int iDateSize = pSmartCardHandler->GetFieldValue(CSmartCardMap::MessageExhibitionDate,
                                                     DateTimeBytes, 6);
    if (iDateSize > 0) {
        bShowMessage = true;
        for (int i = 0; i < iDateSize && bShowMessage; i++) {
            if (DateTimeBytes[i] != 99) {
                bShowMessage = false;
            }
        }
    } else {
        DLOG_WARNING("No MessageExhibitionDate field in the map!\n");
    }

    if (!bShowMessage) {
        time_t MessageDateTime = 0;
        m_pContext->GetProcessSmartCard()->GetDateTimeField(
            pSmartCardHandler, CSmartCardMap::MessageExhibitionDate, &MessageDateTime);

        char cLastUpdate[STRDATETIMELEN];
        DLOG_INFO("Message Exhibition Date: %s\n",
                  CFirmwareUtil::GetDateTimeString(MessageDateTime, cLastUpdate,
                                                   STRDATETIMELEN));

        if (CFirmwareUtil::GetDateInDays(MessageDateTime) ==
            CFirmwareUtil::GetDateInDays(m_Now)) {
            if (pSmartCardHandler->GetFieldValue(CSmartCardMap::MessageExhibitionCounter,
                                                 &m_Messages, 1) == 0)
                return;

            bShowMessage = (m_Messages > 0);
        }
    }

    DLOG_INFO("ShowMessage: %s\n", bShowMessage ? "yes" : "no");
    // se tiver de mostrar a imagem, entao le
    if (bShowMessage) {
        int MessageSize = pSmartCardHandler->GetFieldValue(
            CSmartCardMap::Message, (BYTE *)m_cMessage, sizeof(m_cMessage) - 1);
        if (MessageSize > 0)
            m_cMessage[MessageSize] = 0;
        else {
            DLOG_WARNING("No Message field in the map!\n");
            memset(m_cMessage, ' ', sizeof(m_cMessage) - 1);
            m_cMessage[sizeof(m_cMessage) - 1] = 0;
        }
    }
}

bool CSmartCardValidationOnMRA::CheckPermission(CSmartCardHandler *pSmartCardHandler,
                                                EReader eReader,
                                                WORD *retPermissionId) const
{
    CSmartCardMap::FieldCode PermissionDay = CSmartCardMap::NormalDaysPermission;
    // Verifica o tipo do dia
    switch (CFirmwareUtil::GetDayType(m_pContext->GetHolidayList(), m_Now)) {
    case CFirmwareUtil::Saturday:
        PermissionDay = CSmartCardMap::SaturdayPermission;
        break;
    case CFirmwareUtil::Sunday:
        PermissionDay = CSmartCardMap::SundayPermission;
        break;
    case CFirmwareUtil::Holiday:
        PermissionDay = CSmartCardMap::HolidayPermission;
        break;
    default:
    case CFirmwareUtil::NormalDays:
        PermissionDay = CSmartCardMap::NormalDaysPermission;
        break;
    }

    BYTE permissionData[2];
    // Le a permissao correspondente ao dia atual
    if (pSmartCardHandler->GetFieldValue(PermissionDay, permissionData, 2) == 2) {
        CBuffer data(2);
        data.PutBytes(permissionData, 2);
        data.Flip();
        WORD permissionId = data.GetWord();
        DLOG_INFO("Permissao = %d\n", permissionId);
        if (m_pContext->GetPermissionManager()->GetPermission(eReader, permissionId) !=
            NULL) {
            *retPermissionId = permissionId;
            return true;
        } else {
            return CheckPermissionRestrictedArea(pSmartCardHandler, eReader,
                                                 retPermissionId);
        }
    } else {
        DLOG_WARNING("PERMISSION FIELD SIZE WRONG!\n");
    }
    return false;
}

bool CSmartCardValidationOnMRA::CheckPermissionRestrictedArea(
    CSmartCardHandler *pSmartCardHandler, EReader eReader, WORD *retPermissionId) const
{
    time_t FinalAreaRestrita = 0, InicioAreaRestrita = 0, hrAtual = (m_Now / 60) * 60;
    // char cRestrictedAreaHour[STRDATETIMELEN];
    CSmartCardMap::FieldCode EndRestrictedAreaHour = CSmartCardMap::FinalAreaRestrita1,
                             StartRestrictedAreaHour = CSmartCardMap::InicioAreaRestrita1,
                             PermissionRestrictedAreaID =
                                 CSmartCardMap::PermissaoAreaRestrita1;

    for (int i = 0; i < 3; i++) {
        if (i > 0) {
            EndRestrictedAreaHour = (CSmartCardMap::FieldCode)(
                CSmartCardMap::FinalAreaRestrita1 + ((BYTE)3 * i));
            StartRestrictedAreaHour = (CSmartCardMap::FieldCode)(
                CSmartCardMap::InicioAreaRestrita1 + ((BYTE)3 * i));
            PermissionRestrictedAreaID = (CSmartCardMap::FieldCode)(
                CSmartCardMap::PermissaoAreaRestrita1 + ((BYTE)3 * i));
        }
        BYTE permissionData[2];
        if (pSmartCardHandler->GetFieldValue(PermissionRestrictedAreaID, permissionData,
                                             2) == 2) {
            CBuffer data(2);
            data.PutBytes(permissionData, 2);
            data.Flip();
            WORD permissionId = data.GetWord();
            DLOG_INFO("Permissao adicional %d = %d\n", i + 1, permissionId);
            if (m_pContext->GetPermissionManager()->GetPermission(eReader,
                                                                  permissionId) != NULL) {
                int FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
                    pSmartCardHandler, StartRestrictedAreaHour, &InicioAreaRestrita);
                if (FieldSize >= 2 && FieldSize <= 6) {
                    int FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
                        pSmartCardHandler, EndRestrictedAreaHour, &FinalAreaRestrita);
                    if (FieldSize >= 2 && FieldSize <= 6) {
                        if ((hrAtual >= InicioAreaRestrita) &&
                            (hrAtual <= FinalAreaRestrita)) {
                            *retPermissionId = permissionId;
                            return true;
                        } else {
                            DLOG_INFO("Fora do periodo para uso da permissao\n");
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool CSmartCardValidationOnMRA::CheckSituation(CSmartCardHandler *pSmartCardHandler) const
{
    DLOG_INFO("CheckSituation: (0x%02X)\n", m_PeopleKindSit);
    return GET_SITUATION(m_PeopleKindSit) == 10;
}

bool CSmartCardValidationOnMRA::CheckValidity(CSmartCardHandler *pSmartCardHandler,
                                              CAccessEvent *pEvent) const
{
    time_t Validity = 0;
    int FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::Validity, &Validity);
    if ((FieldSize == 5 || FieldSize == 4) && !CHECK_NO_DATE(Validity)) {
        if (Validity <= m_Now) {
            pEvent->SetValidity(Validity);
            return false;
        }
    }
    return true;
}

bool CSmartCardValidationOnMRA::CheckLevel(CSmartCardHandler *pSmartCardHandler,
                                           CAccessEvent *pEvent,
                                           const CFirmwareProperties *pProperties,
                                           const CReaderConfig *pReaderConfig)
{
    const int ReaderLevel1 = pProperties->GetReaderLevel1(m_eReader);
    const int ReaderLevel2 = pProperties->GetReaderLevel2(m_eReader);
    DLOG_INFO("[CheckLevel] ReaderLevel(%d, %d) - CardLevel(%d)\n", ReaderLevel1,
              ReaderLevel2, m_OriginalLevel);

    if (m_OriginalLevel == EMPTY_LEVEL || m_OriginalLevel == ReaderLevel1) {
        m_NewLevel = ReaderLevel2;
        m_LevelDir = LD_N1ToN2;
    } else if (m_OriginalLevel == ReaderLevel2) {

        if (pProperties->IsReaderBothDirections(m_eReader)) {
            m_NewLevel = ReaderLevel1;
            m_LevelDir = LD_N2ToN1;
        } else {
            // se nao for ambos os sentidos continua como esta
            m_NewLevel = m_OriginalLevel;
            m_LevelDir = LD_N1ToN2;
        }

    } else {
        if (ReaderLevel1 < ReaderLevel2)
            pEvent->SetFlowType(3); // entrar em nivel superior sem passar pelo anterior
        else if (ReaderLevel1 > ReaderLevel2)
            pEvent->SetFlowType(4); // sair de nivel inferior sem passar pelo anterior
        else if (m_OriginalLevel < ReaderLevel1)
            pEvent->SetFlowType(3); // entrar em nivel superior sem passar pelo anterior
        else
            pEvent->SetFlowType(4); // sair de nivel inferior sem passar pelo anterior
        return false;
    }
    m_bLevelChanged = true;
    return true;
}

bool CSmartCardValidationOnMRA::CheckRemoval(CSmartCardHandler *pSmartCardHandler,
                                             CAccessEvent *pEvent) const
{
    time_t StartDate, EndDate;

    int FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::StartRemoval, &StartDate);
    if ((FieldSize == 4 || FieldSize == 3) && !CHECK_NO_DATE(StartDate)) {
        FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
            pSmartCardHandler, CSmartCardMap::EndRemoval, &EndDate);
        if (FieldSize == 4 || FieldSize == 3) {
            if (CHECK_NO_DATE(EndDate))
                EndDate = INT_MAX; // Seta a ultima data possível
            else if (FieldSize == 3)
                EndDate += SECONDS_PER_DAY - 1; // Ajusta para o ultimo segundo do dia

            pEvent->SetRemovalPeriod(StartDate, EndDate);

            // Verifica se a data atual esta entre as datas de afastamento
            return m_Now < StartDate || m_Now > EndDate;
        }
    }
    return true;
}

void CSmartCardValidationOnMRA::GetCreditRange(CSmartCardHandler *pSmartCardHandler,
                                               time_t DayTimeInMinutes,
                                               bool bCheckCredits,
                                               short *pRangeNumber) const
{

    // o retorno é da seguinte forma, -1 negado crédigo, -2 fora da faixa de
    // consumo
    *pRangeNumber = -1;

    // Decrementa o credito de acesso correspondente a faixa do horario atual
    BYTE CreditRange[3];
    for (int i = 0; i < 6; i++) {

        CSmartCardMap::FieldCode Field =
            (CSmartCardMap::FieldCode)(CSmartCardMap::RefectoryRange1 + i);

        if (pSmartCardHandler->GetFieldValue(Field, CreditRange, 3) == 3 &&
            IsInHourlyRange(DayTimeInMinutes, CreditRange)) {
            if (bCheckCredits) {
                Field =
                    (CSmartCardMap::FieldCode)(CSmartCardMap::RefectoryCreditRange1 + i);
                BYTE bCreditCounter = 0;
                pSmartCardHandler->GetFieldValue(Field, &bCreditCounter, 1);
                DLOG_INFO("Faixa: %d - Creditos: %d - Checa Credito: %d\n", i,
                          bCreditCounter, bCheckCredits);
                if (bCreditCounter > 0) {
                    // Aqui a pessoa esta dentro da faixa e possui credito,
                    // entao retorna a faixa de consumo
                    *pRangeNumber = i;
                    return;
                } else {
                    // Se chegou aqui, a pessoa está dentro da faixa e não tem
                    // credito
                    *pRangeNumber = -1;
                    return;
                }
            }
            // Se chegou aqui, a pessoa está dentro da faixa e não checa credito
            *pRangeNumber = i;
            return;
        }
    }
    // Se chegou aqui, o acesso não esta dentro de nenhuma faixa.
    *pRangeNumber = -2;
}

short CSmartCardValidationOnMRA::CheckCredit(CSmartCardHandler *pSmartCardHandler,
                                             short *pRangeNumber)
{
    const time_t CurrentTime = CFirmwareUtil::GetTimeInSeconds(m_Now);

    DLOG_INFO("Credito de Acesso: \n");
    if (m_CreditControlType == Control_Quota) // Se possui credito tem acesso liberado
    {
        DLOG_INFO("Por Quota. \n");
        GetCreditRange(pSmartCardHandler, CurrentTime / 60, true, pRangeNumber);
        return *pRangeNumber;
    } else if (m_CreditControlType == No_Control_Range) {
        DLOG_INFO("por faixa, sem limite.\n");
        GetCreditRange(pSmartCardHandler, CurrentTime / 60, false, pRangeNumber);
    } else if (m_CreditControlType == Control_Range) {
        DLOG_INFO("por faixa, limitado. \n");
        GetCreditRange(pSmartCardHandler, CurrentTime / 60, true, pRangeNumber);
    }

    if (*pRangeNumber >= 0) // Se tem creditos, verifica a ultima passagem
    {
        const WORD CurrentDate = CFirmwareUtil::GetDateInDays(m_Now);

        time_t LastRefectoryPass;
        int FieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
            pSmartCardHandler, CSmartCardMap::LastRefectoryPassDateTime,
            &LastRefectoryPass);
        if (FieldSize == 4 || FieldSize == 5) {
            char cDateTime[STRDATETIMELEN];
            DLOG_INFO("Ultima passagem refeitorio: %s \n",
                      CFirmwareUtil::GetDateTimeString(LastRefectoryPass, cDateTime,
                                                       STRDATETIMELEN));
            const WORD LastRefectoryPassDate =
                CFirmwareUtil::GetDateInDays(LastRefectoryPass);

            // TODO: Checar esta verificação, parece estranha
            if (CurrentDate == LastRefectoryPassDate) // Se mudou o dia jah esta liberado
            { // Se for o mesmo dia verifica a hora
                const time_t LastPassTime =
                    CFirmwareUtil::GetTimeInSeconds(LastRefectoryPass);
                short LastPassRange = -1;
                GetCreditRange(pSmartCardHandler, LastPassTime / 60, false,
                               &LastPassRange);
                if (*pRangeNumber != LastPassRange) {
                    // Se não estiver na mesma faixa pode passar
                    return *pRangeNumber;
                }
                // Se estiver na mesma faixa nega
                return -1;
            }
        }
        // Se não possui o campo da ultima passagem no refeitorio esta liberado
        return *pRangeNumber;
    }

    return *pRangeNumber;
}

bool CSmartCardValidationOnMRA::CheckAntiPassBack(CSmartCardHandler *pSmartCardHandler,
                                                  CAccessEvent *pEvent,
                                                  const CFirmwareProperties *pProperties,
                                                  const CReaderConfig *pReaderConfig)
{
    const BYTE ReaderLevel1 = pProperties->GetReaderLevel1(m_eReader);
    const BYTE ReaderLevel2 = pProperties->GetReaderLevel2(m_eReader);
    DLOG_INFO("[CheckAntiPass] ReaderLevel(%d, %d) - CardLevel(%d)\n", ReaderLevel1,
              ReaderLevel2, m_OriginalLevel);

    if (!CheckTimeOutAntiPassBack(pSmartCardHandler, pReaderConfig)) {
        if (m_OriginalLevel == ReaderLevel2) {
            // se o nivel for igual a Destino, bloqueia!
            if (ReaderLevel1 <= ReaderLevel2)
                pEvent->SetFlowType(1); // entrar sem sair
            else if (ReaderLevel1 > ReaderLevel2)
                pEvent->SetFlowType(2); // sair sem entrar
            return false;
        } else {
            // Tudo que vier diferente, atualiza pro nivel 2
            m_NewLevel = ReaderLevel2;
            m_bLevelChanged = true;
        }
    }
    return true;
}

bool CSmartCardValidationOnMRA::CheckPersonHourlyRange(
    CSmartCardHandler *pSmartCardHandler, const CReaderConfig *pReaderConfig) const
{
    bool bReaderCheckTimeKeeping =
        (pReaderConfig->GetReaderType() == CReaderConfig::Ponto ||
         pReaderConfig->GetReaderType() == CReaderConfig::AcessoPonto);
    bool bReaderCheckAccess =
        (pReaderConfig->GetReaderType() == CReaderConfig::Acesso ||
         pReaderConfig->GetReaderType() == CReaderConfig::AcessoPonto);
    BYTE WeekDay = CFirmwareUtil::GetBrokedDateTime(m_Now).tm_wday;
    const WORD CurrentTime = CFirmwareUtil::GetTimeInSeconds(m_Now) / 60;
    BYTE Range[21];

    // Verificar faixa horaria de acesso
    if (m_bCheckHourlyRangeAccess && bReaderCheckAccess) {
        DLOG_INFO("Faixa horaria de acesso da pessoa:\n");
        CSmartCardMap::FieldCode AccessRangeField =
            (CSmartCardMap::FieldCode)(CSmartCardMap::SundayAccessRange + WeekDay);
        int Size =
            pSmartCardHandler->GetFieldValue(AccessRangeField, Range, sizeof(Range));
        for (int i = 0; i < Size; i += 3) {
            if (IsInHourlyRange(CurrentTime, Range + i)) {
                DLOG_INFO("Faixa: %d \n", i / 3);
                return true;
            }
        }
        DLOG_INFO("Nenhuma faixa encontrada\n");
    }

    // Verificar faixa horaria de ponto
    if (m_bCheckHourlyRangeTimeKeeping && bReaderCheckTimeKeeping) {
        DLOG_INFO("Faixa horaria de ponto da pessoa: \n");
        CSmartCardMap::FieldCode TimeKeepingRangeField =
            (CSmartCardMap::FieldCode)(CSmartCardMap::SundayTimeKeepingRange + WeekDay);
        int Size =
            pSmartCardHandler->GetFieldValue(TimeKeepingRangeField, Range, sizeof(Range));

        for (int i = 0; i < Size; i += 3) {
            if (IsInHourlyRange(CurrentTime, Range + i)) {
                DLOG_INFO("Faixa: %d \n", i / 3);
                return true;
            }
        }
        DLOG_INFO("Nenhuma faixa encontrada\n");
    }

    return false;
}

bool CSmartCardValidationOnMRA::CheckPermissionHourlyRange(
    CSmartCardHandler *pSmartCardHandler, EReader eReader, WORD PermissionID) const
{
    const WORD CurrentTime = CFirmwareUtil::GetTimeInSeconds(m_Now) / 60;
    const CPermission *pPermission =
        m_pContext->GetPermissionManager()->GetPermission(eReader, PermissionID);
    if (pPermission) {
        int iFaixaHoraria = pPermission->GetHouryRangeIndex(CurrentTime);
        DLOG_INFO("Permissao de Acesso: %d, Faixa horaria da permissao: %d\n",
                  PermissionID, iFaixaHoraria);
        return (iFaixaHoraria >= 0);
    }
    return false;
}

bool CSmartCardValidationOnMRA::CheckPersonType(CSmartCardHandler *pSmartCardHandler,
                                                WORD EnabledPersonTypes) const
{
    if (EnabledPersonTypes != CReaderConfig::ALL_PERSON_TYPES) {
        WORD PersonType = GET_PERSON_TYPE(m_PeopleKindSit);
        DLOG_INFO("Tipo da pessoa 0x%X - Tipos Habilitados: 0x%04X\n", PersonType,
                  EnabledPersonTypes);
        return PersonType & EnabledPersonTypes;
    }
    return true;
}

bool CSmartCardValidationOnMRA::IsMasterCard() const
{
    return (CReaderConfig::MASTER_CARD & GET_PERSON_TYPE(m_PeopleKindSit));
}

/*
 *  Time out do controle da anti-dupla, se timeout > 0 controla o tempo, senao
 * sempre bloqueia a anti-dupla
 */
bool CSmartCardValidationOnMRA::CheckTimeOutAntiPassBack(
    CSmartCardHandler *pSmartCardHandler, const CReaderConfig *pReaderConfig)
{

    // timeout em minutos
    WORD TimeOut = pReaderConfig->GetTimeOutAntiPassBack();
    // caso não tenha timeout configurado bloqueia sempre a antidupla (timeout
    // == 0 )
    if (TimeOut == 0) {
        return false;
    }

    // guarda a data do ultimo acesso valido.
    time_t LastPassDate;
    int DateFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastPassDate, &LastPassDate);

    // o controle da anti-dupla irá funcionar somente se o campo ultima passagem
    // possuir a data e hora da passagem
    if (DateFieldSize == 4) {
        // verifica se a data/hora da ultima passagem mais o timeout é menor que
        // a data/hora atual.
        return ((LastPassDate + (TimeOut * 60)) <
                CFirmwareUtil::GetLocalDateTime(
                    m_pContext->GetConfiguration()->GetProperties()));
    } else {
        DLOG_INFO("O mapa do cartao nao suporta o controle do timeout para "
                  "anti-dupla\n");
        return false;
    }
}

bool CSmartCardValidationOnMRA::CheckLastPassDate(CSmartCardHandler *pSmartCardHandler)
{
    int bValue = -1; // -1 significa que não há campos de data de passagem no
                     // mapa do cartao

    // Le a data da ultima atualização do cartão
    time_t LastOnlineUpdate;
    int DateFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LastOnLineUpdateID, &LastOnlineUpdate);
    if (DateFieldSize == 4 || DateFieldSize == 6) {
        bValue = (LastOnlineUpdate + m_PendingDays * SECONDS_PER_DAY) >= m_Now;
    }
    SetUseField(CSmartCardMap::LastOnLineUpdateID, FALSE);

    if (bValue < 1) {
        time_t LastPassDate;
        DateFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
            pSmartCardHandler, CSmartCardMap::LastPassDate, &LastPassDate);
        if (DateFieldSize == 3 || DateFieldSize == 4) {
            bValue = CFirmwareUtil::GetDateInDays(LastPassDate) + m_PendingDays >=
                     CFirmwareUtil::GetDateInDays(m_Now);
        }
    }
    SetUseField(CSmartCardMap::LastPassDate, FALSE);

    return bValue != 0;
}

bool CSmartCardValidationOnMRA::CheckLunchInterval(CSmartCardHandler *pSmartCardHandler,
                                                   EReader eReader) const
{
    time_t hrNow = 0, LunchIntervalStart = 0;
    char cLunchHour[STRDATETIMELEN];
    BYTE WeekDay = CFirmwareUtil::GetBrokedDateTime(m_Now).tm_wday;

    BYTE buffer[2];
    int FieldSize =
        pSmartCardHandler->GetFieldValue(CSmartCardMap::TempoIntervaloAlmoco, buffer, 2);
    if (FieldSize == 2) {
        CBuffer data(2);
        data.PutBytes(buffer, 2);
        data.Flip();
        WORD LunchIntervalDuration = data.GetWord();
        BYTE Range[21];
        if (ReadLunchIntervalInfo(pSmartCardHandler, Range, LunchIntervalStart)) {
            DLOG_INFO("LunchControlStartDate %s\n",
                      CFirmwareUtil::GetDateTimeString(LunchIntervalStart, cLunchHour,
                                                       STRDATETIMELEN));

            const WORD CurrentDate = CFirmwareUtil::GetDateInDays(m_Now);
            const WORD LunchControlDate =
                CFirmwareUtil::GetDateInDays(LunchIntervalStart);

            if (CurrentDate == LunchControlDate) // Se mudou o dia jah esta liberado
            {
                // Verifica se a data/hora atual ou se a data/hora de
                // LunchControlStartDate está dentro da faixa horária de almoço
                const time_t hour = CFirmwareUtil::GetTimeInSeconds(m_Now);
                const time_t LunchStart =
                    CFirmwareUtil::GetTimeInSeconds(LunchIntervalStart);

                if (IsInHourlyRange(LunchStart / 60, Range + (WeekDay * 3)) ||
                    IsInHourlyRange(hour / 60, Range + (WeekDay * 3))) {
                    // zera a data para somente considerar a hora
                    tm date;
                    date = CFirmwareUtil::GetBrokedDateTime(m_Now);
                    hrNow = CFirmwareUtil::GetDateTime(1, 1, 1970, date.tm_hour,
                                                       date.tm_min, 0);
                    date = CFirmwareUtil::GetBrokedDateTime(LunchIntervalStart);
                    LunchIntervalStart = CFirmwareUtil::GetDateTime(
                        1, 1, 1970, date.tm_hour, date.tm_min, 0);
                    // agora o teste
                    if ((hrNow - LunchIntervalStart) >= (LunchIntervalDuration * 60)) {
                        return true;
                    }
                } else
                    return true;
            } else
                return true;
        } else
            return true;
    }
    return false;
}

bool CSmartCardValidationOnMRA::CheckInterJourney(CSmartCardHandler *pSmartCardHandler,
                                                  EReader eReader) const
{
    time_t InterJourneyStart = 0;
    char cInterJourneyHour[STRDATETIMELEN];
    short InterJourneyTolerance = 0;
    BYTE WeekDay = CFirmwareUtil::GetBrokedDateTime(m_Now).tm_wday;

    // lê a data/hora da última saída
    int iFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LunchControlStartDate, &InterJourneyStart);
    if (iFieldSize == 0) {
        DLOG_INFO("[CheckInterJourney] no LunchControlStartDate on smart card map\n");
        return false;
    }
    DLOG_INFO("[CheckInterJourney] LunchControlStartDate %s\n",
              CFirmwareUtil::GetDateTimeString(InterJourneyStart, cInterJourneyHour,
                                               STRDATETIMELEN));
    // lê a tolerância
    InterJourneyTolerance = (m_InterJourney & 0x0FFF);
    DLOG_INFO("[CheckInterJourney] InterJourneyTolerance %d\n", InterJourneyTolerance);

    const time_t hourSec = CFirmwareUtil::GetTimeInSeconds(m_Now);
    const time_t InterJourneyStartSec =
        CFirmwareUtil::GetTimeInSeconds(InterJourneyStart);

    BYTE Range[21];
    iFieldSize = pSmartCardHandler->GetFieldValue(CSmartCardMap::RefectoryAccessRange,
                                                  Range, sizeof(Range));
    if (iFieldSize == 21) {
        if (!(IsInHourlyRange(InterJourneyStartSec / 60, Range + (WeekDay * 3)) ||
              IsInHourlyRange(hourSec / 60, Range + (WeekDay * 3)))) {
            const time_t diferMin = (m_Now - InterJourneyStart) / 60;
            DLOG_INFO("[CheckInterJourney] Diference: %ld, InterJourneyTime: %d\n",
                      diferMin, m_pContext->GetConfiguration()->GetInterJourneyTime());
            if (diferMin <= (m_pContext->GetConfiguration()->GetInterJourneyTime())) {
                DLOG_INFO("Ultima saida menos hora atual menor que tempo da "
                          "interjornada\n");
                if (diferMin >= InterJourneyTolerance) {
                    DLOG_INFO("Ultima saida menos hora atual maior que tolerancia\n");
                    return false;
                } else {
                    // Ta ainda na tolerância para entrar
                    return true;
                }
            } else {
                return true;
            }
        } else {
            return true;
        }
    } else {
        DLOG_WARNING("[CheckInterJourney] RefectoryAccessRange with wrong size (%d) "
                     "on smart card map\n",
                     iFieldSize);
        return true;
    }
    return false;
}

bool CSmartCardValidationOnMRA::CheckMinimumStayTime(CSmartCardHandler *pSmartCardHandler,
                                                     EReader eReader,
                                                     const BYTE Staytime) const
{
    if (Staytime == 0) {
        return true;
    }

    time_t MinimumStayTime = 0;
    int iFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::MinimumStayTimeDateTime, &MinimumStayTime);
    DLOG_INFO("Tamanho campo= %d\n", iFieldSize);
    if (iFieldSize == 0) {
        DLOG_INFO("[CheckMinimumStayTime] no MinimumStayTimeDateTime on smart card "
                  "map\n");
        return false;
    }
    char cMinimumStayTime[STRDATETIMELEN];
    DLOG_INFO("MinimumStayTimeDateTime %s - StayTime: %d\n",
              CFirmwareUtil::GetDateTimeString(MinimumStayTime, cMinimumStayTime,
                                               STRDATETIMELEN),
              Staytime);

    const WORD CurrentTime = CFirmwareUtil::GetTimeInSeconds(m_Now) / 60;
    const WORD MinimumStayTimeMin = CFirmwareUtil::GetTimeInSeconds(MinimumStayTime) / 60;

    if ((CurrentTime - MinimumStayTimeMin) >= Staytime) {
        return true;
    }
    return false;
}

bool CSmartCardValidationOnMRA::LunchCreditControl(CSmartCardHandler *pSmartCardHandler,
                                                   EReader eReader,
                                                   const BYTE bOperation) const
{
    // pega as faixas do dia em questão
    const CRefectoryControl *pRefControl =
        m_pContext->GetRefectoryControlManager()->GetRefectoryControl(
            CFirmwareUtil::GetDayType(m_pContext->GetHolidayList(), m_Now));
    const time_t DayTimeInMinutes = CFirmwareUtil::GetTimeInSeconds(m_Now) / 60;

    // verifica se o campo existe no smart para depois gravá-lo
    BYTE LunchControlRange[3];
    int iFieldSize = pSmartCardHandler->GetFieldValue(CSmartCardMap::RefectoryRange1,
                                                      LunchControlRange, 3);
    if (iFieldSize == 0) {
        DLOG_INFO("[LunchCreditControl] campo reserva de almoco inexistente no "
                  "mapa\n");
        return false;
    }

    if (!pRefControl) {
        DLOG_INFO("[LunchCreditControl] Nenhuma faixa de reserva/consumo "
                  "cadastrada\n");
        return false;
    }

    // identifica o tipo da operação
    if (bOperation == 255 || bOperation == 4) // reserva automática ou manual
    {
        if (pRefControl->GetHourlyRange(DayTimeInMinutes, LunchControlRange)) {
            // grava a hora do consumo no cartão
            pSmartCardHandler->SetFieldValue(CSmartCardMap::RefectoryRange1,
                                             LunchControlRange, 3);
            DLOG_INFO("[LunchCreditControl] Almoco reservado\n");
            return true;
        } else {
            DLOG_INFO("[LunchCreditControl] Hora atual nao pertence a nenhuma "
                      "faixa horaria cadastrada\n");
        }
    } else if (bOperation == 1) // consumo -> momento da passagem no refeitório
    {
        // verifica se a hora atual está entre os dados lidos do cartão
        if (IsInHourlyRange(DayTimeInMinutes, LunchControlRange) ||
            pRefControl->GetZoneCount() == 0) {
            // apaga agora as informações para zerar o campo
            memset(LunchControlRange, 0, sizeof(LunchControlRange));
            pSmartCardHandler->SetFieldValue(CSmartCardMap::RefectoryRange1,
                                             LunchControlRange, 3);
            DLOG_INFO("[LunchCreditControl] Almoco consumido\n");
            return true;
        } else {
            DLOG_INFO("[LunchCreditControl] Fora do horario de consumo\n");
        }
    } else if (bOperation == 5) // cancelamento
    {
        // apaga as informações do cartão
        if (pRefControl->CanCancelLunch(DayTimeInMinutes, LunchControlRange)) {
            memset(LunchControlRange, 0, sizeof(LunchControlRange));
            pSmartCardHandler->SetFieldValue(CSmartCardMap::RefectoryRange1,
                                             LunchControlRange, 3);
            DLOG_INFO("[LunchCreditControl] Almoco cancelado\n");
            return true;
        } else {
            DLOG_INFO("[LunchCreditControl] Cancelamento de reserva nao pode ser "
                      "feito\n");
        }
    }
    return false;
}

bool CSmartCardValidationOnMRA::ReadPassword(CSmartCardHandler *pSmartCardHandler)
{
    int iSize = pSmartCardHandler->GetFieldValue(CSmartCardMap::AccessPassword,
                                                 m_pPassword, sizeof(m_pPassword));
    DLOG_INFO("Lendo campo de senha (Tamanho: %d)\n", iSize);

    if (iSize > 0) {
        return true;
    }
    return false;
}

bool CSmartCardValidationOnMRA::ReadLunchIntervalInfo(
    CSmartCardHandler *pSmartCardHandler, BYTE *Range, time_t &LunchIntervalStart) const
{
    int iFieldSize = m_pContext->GetProcessSmartCard()->GetDateTimeField(
        pSmartCardHandler, CSmartCardMap::LunchControlStartDate, &LunchIntervalStart);
    DLOG_INFO("Tamanho campo= %d\n", iFieldSize);
    if (iFieldSize == 0) {
        DLOG_INFO("[CheckLunchInterval] no LunchControlStartDate on smart card "
                  "map\n");
        return false;
    }

    iFieldSize =
        pSmartCardHandler->GetFieldValue(CSmartCardMap::RefectoryAccessRange, Range, 21);
    if (iFieldSize != 21) {
        DLOG_INFO("[CheckLunchInterval] RefectoryAccessRange with wrong size (%d) "
                  "on smart card map\n",
                  iFieldSize);
        return false;
    }
    return true;
}

void CSmartCardValidationOnMRA::SetBackupList(CValBackup *pBackupList)
{
    fBackupList = pBackupList;
}
} // namespace seguranca

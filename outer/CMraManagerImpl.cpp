/*
 * CMraManagerImpl.cpp
 *
 *  Created on: 10/09/2012
 *      Author: digicon
 */

#include "CMraManagerImpl.h"
#include "CAccessEvent.h"
#include "CAlarmEvent.h"
#include "CBiometricException.h"
#include "CBiometricTemplate.h"
#include "CBiometricUser.h"
#include "CCommand.h"
#include "CContext.h"
#include "CDevice.h"
#include "CEventManager.h"
#include "CException.h"
#include "CFingerPrintManagerImpl.h"
#include "CFirmwareUtil.h"
#include "CInvalidDataException.h"
#include "CMCA.h"
#include "CMRAImpl.h"
#include "CMRAReader.h"
#include "CManufacturerManager.h"
#include "CManufacturerManagerCreator.h"
#include "CNoMemoryException.h"
#include "COutputSocket.h"
#include "CPermissionManager.h"
#include "CPersonManager.h"
#include "CREManager.h"
#include "CReturn.h"
#include "CSmartCardHandler.h"
#include "CSmartCardMap.h"
#include "CStateTable.h"
#include "CStreamFactory.h"
#include "CThread.h"
#include "CValidationResult.h"
#include "dlog.h"
#include <unistd.h>

using namespace base;

#define CHECK_MRA_ENABLED(x, y) (((x & 0x3F0000) >> 16) & (1 << y))

namespace seguranca
{

CMraManagerImpl::CMraManagerImpl(CMCA &mca, CDevice &device, CContext &ctx)
    : m_mca(mca), m_device(device), m_ctx(ctx)
{
    // TODO Auto-generated constructor stub

    // Cria referência para a mesma lista de links biométricos em
    // CFingerPrintManagerImpl...
    m_FingerLinks = m_ctx.GetFingerPrintManager()->GetList();

    // Dispara o timer para a contagem de tempo para requisição dos eventos
    for (UINT i = 0; i < CMCA::MAX_MRA_READERS; i++) {
        CMCA::EMRAReader mraReaderId = (CMCA::EMRAReader)(i);
        m_mca.GetMRAReader(mraReaderId)->cleanStopwatch();
    }
}

CMraManagerImpl::~CMraManagerImpl()
{
    // TODO Auto-generated destructor stub
}

void CMraManagerImpl::SetWldOverModule(WORD wId) { m_readerOp.m_wIdOverModule = wId; }

// Retorna se existe algum evento de leitura a realizar
BYTE CMraManagerImpl::HasEvent(CMCA::EMRAReader EMraReaderId)
{
    BYTE resp;

    try {
        resp = m_mca.GetMRAReader(EMraReaderId)->read((int)EMraReaderId);
        if (!resp) {
            DBG_MRA("Leitor utilizado %d\n",
                    m_mca.GetMRAReader(EMraReaderId)->GetBioTechUsed());
            if (m_mca.GetMRAReader(EMraReaderId)->GetBioTechUsed() == BT_SAGEM) {
                SetWldOverModule(
                    m_mca.GetMRAReader(EMraReaderId)->GetFingerPrintNumberId());
            }
            mraReaderId = EMraReaderId;
        }
    } catch (CException &ex) {
        DLOG_ERROR("MRA Reader[%d]: Timeout de comunicacao!\n", EMraReaderId);
        return resp = 1;
    }
    return resp;
}

// Retorna se existe algum evento de leitura a realizar
int CMraManagerImpl::HasEvent(CMCA::EMRAReader EMraReaderId, const UINT keepAliveTimeout)
{
    BYTE resp = 0;
    struct timeval tv = m_mca.GetMRAReader(EMraReaderId)->GetKeepAliveInteval();
    try {
        // Testa se o tempo de verificação atingiu o limite configurado
        // KeepAlive é passado em milisegundos, portanto ms/1000=segundos
        //        DBG_MRA("m_mca.GetMRAReader(EMraReaderId)->TimeElapsedComm(&tv):
        //        %d\n", m_mca.GetMRAReader(EMraReaderId)->TimeElapsedComm(&tv))
        //        DBG_MRA("keepAliveTimeout / 1000: %d\n", keepAliveTimeout /
        //        1000);
        if (m_mca.GetMRAReader(EMraReaderId)->TimeElapsedComm(&tv) >=
            (keepAliveTimeout / 1000)) {
            resp = m_mca.GetMRAReader(EMraReaderId)->RequestingLogs();
            // Testa se recebeu algum log. Caso contrário restaura o contador e
            // aguarda o timeout para nova consulta
            if (!resp) {
                // Recomeça a contagem de tempo para nova requisição de logs
                m_mca.GetMRAReader(EMraReaderId)->cleanStopwatch();
                return -2;
            }
        } else {
            return 0;
        }
    } catch (CException &ex) {
        DLOG_ERROR("MRA Reader[%d]: Timeout de comunicacao!\n", EMraReaderId);
        return -1;
    }
    // Recomeça a contagem de tempo para nova requisição de logs
    m_mca.GetMRAReader(EMraReaderId)->cleanStopwatch();
    return resp;
}

// Processa os eventos recebidos
void CMraManagerImpl::ProcessesEvents(CMCA::EMRAReader EMraReaderId, int numEvents)
{
    // EMraReaderId é o índice de MRAs(0...5)
    DBG_MRA("EMraReaderId: %d\n", EMraReaderId);
    DBG_MRA("Numero de eventos: %d\n", numEvents);

    CFirmwareProperties *pFirmProps = &m_ctx.GetConfiguration()->GetProperties();

    // De acordo com a quantidade, coloca na lista para envio ao DFS
    for (int i = 0; i < numEvents; i++) {
        try {
            // Coloca os dados a disposição para o uso
            m_mca.GetMRAReader(EMraReaderId)->GetEventData();

            // Identifica o LOG recebido. Compatibiliza com os eventos
            // disponíveis no firmware
            int typeEvent = EventInterpreter(EMraReaderId);

            DBG_MRA("Id do evento(tipo): %d\n", typeEvent);

            if ((typeEvent == CEvent::ACCESS_GRANTED) ||
                (typeEvent == CEvent::ACCESS_DENIED_WHITE_LIST) ||
                (typeEvent == CEvent::ACCESS_DENIED_BLACK_LIST)) {

                // GMT
                time_t GMTZeroTime = m_mca.GetMRAReader(EMraReaderId)->GetEventInterval();
                CAccessEvent aEvent(CFirmwareUtil::LocalToGMTDateTime(
                    GMTZeroTime, m_ctx.GetConfiguration()->GetProperties()));

                // ID do evento
                aEvent.SetId((CEvent::EventCode)typeEvent);

                // Evento ocorrido em modo on-line, com a mcanet ou com a
                // concentradora?
                // Com a mcanet, mra não fala com a concentradora - Aleixo
                // 19.02.14
                if (!m_mca.GetMRAReader(EMraReaderId)->isRemoteValidation()) {
                    aEvent.SetOnline(false);
                } else {
                    aEvent.SetOnline(true);
                }

                // Direção de acesso: 1-entrada, 2-saída
                DBG_MRA("Direção de acesso: %d \n",
                        pFirmProps->GetAccessDirection((EReader)(EMraReaderId + R_MRA_1),
                                                       true));
                aEvent.SetDirection(pFirmProps->GetAccessDirection(
                    (EReader)(EMraReaderId + R_MRA_1), true));

                // Tipo do identificador?
                // Obedece o que é setado em SetCard()

                // Quando identificação(validação) por cartão
                CCard m_card;
                ULONGLONG llID = strtoull(
                    (char *)m_mca.GetMRAReader(EMraReaderId)->GetDataEvent(), NULL, 10);

                // Quando identificação(validação) por cartão?
                if ((m_mca.GetMRAReader(EMraReaderId)->GetLastTechUsed() > 0) &&
                    (m_mca.GetMRAReader(EMraReaderId)->GetLastTechUsed() <= 2)) {

                    m_card.SetPerson(m_mca.GetMRAReader(EMraReaderId)->GetDataEvent());
                    aEvent.SetCard(m_card);
                    aEvent.SetPersonId(m_card.GetPerson());
                    m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(0);
                } else {
                    m_card.SetId(llID);
                    aEvent.SetPersonId(m_card.GetPerson());
                    aEvent.SetCard(m_card);
                    m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(0);
                }

                // Código da leitora
                aEvent.SetReader((EReader)(R_MRA_1 + EMraReaderId));

                // Tecla digitada
                aEvent.SetKeyPressed(0xFF);

                // Nível do cartão
                aEvent.SetLevel(0x00);

                // Faixa de crédito de acesso
                aEvent.SetAccessCredits(0xFF);

                // Id do cartão do veículo
                CCard tempCard;
                tempCard.SetId(0LL);
                aEvent.SetVehicleCard(tempCard);

                // Processa evento
                CValidationResult valRes;
                valRes.SetEvent(aEvent);
                m_ctx.GetEventManager()->ProcessEvent(valRes.GetEvent(),
                                                      m_ctx.IsOnline());

            } else if (typeEvent == CEvent::FIRMWARE_STARTED) {

                CAlarmEvent event((CEvent::EventCode)typeEvent, false, 0,
                                  (EReader)(EMraReaderId + R_MRA_1 + 1));
                m_ctx.GetEventManager()->ProcessEvent(event, false);
            } else {
                DBG_MRA("NAO SEI QUE EVENTO EH ESSE!\n");
                DBG_MRA("NAO VOU FAZER NADA!\n")
            }

        } catch (CException &ex) {
            DLOG_ERROR("MRA Reader[%d]: Timeout de comunicacao!\n", EMraReaderId);
            return;
        }
    }
    // Libera a memória alocada para receber os logs
    m_mca.GetMRAReader(EMraReaderId)->DestroyEventsData();
}

// Identifica se o evento recebido é compativel com os do firmware
int CMraManagerImpl::EventInterpreter(CMCA::EMRAReader EMraReaderId)
{

    switch (m_mca.GetMRAReader(EMraReaderId)->GetEventId()) {

    case 0x5D: // Autenticando mifare
    case 0x5E: // Autenticando codigo de barras
    case 0x5F: // Autenticando rfid
        if (m_mca.GetMRAReader(EMraReaderId)->GetEventId() == 0x5D) {
            m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(CMRAReader::TECH_MIFARE);
        } else if (m_mca.GetMRAReader(EMraReaderId)->GetEventId() == 0x5E) {
            m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(CMRAReader::TECH_BARRAS);
        } else {
            m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(CMRAReader::TECH_RFID);
        }
        return -3;

    case 0x60: // Autenticando Sagem
        m_mca.GetMRAReader(EMraReaderId)->SetLastTechUsed(CMRAReader::TECH_SAGEM);
        return -3;
    case 0x6C:
    case 0x6B:
        return CEvent::ACCESS_GRANTED;
    case 0x6D:
        return CEvent::ACCESS_DENIED_WHITE_LIST;
    case 0x6E:
        return CEvent::ACCESS_DENIED_BLACK_LIST;
    case 0x62:
    case 0x63:
    case 0x64:
        return CEvent::INPUT_CHANGED;
    case 0x71:
        return CEvent::FIRMWARE_STARTED;
    default:
        return -1;
    }

    return -2;
}

// Autentica o setor do SmartCard pelo MRA
bool CMraManagerImpl::AuthenticateSmartOnMRA(CMCA::EMRAReader EMraReaderId, BYTE nSector)
{
    // chaves padrao de smart card
    static const BYTE DEFAULT_KEY_1[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const BYTE DEFAULT_KEY_2[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};

    const BYTE *KeysArray[] = {
        DEFAULT_KEY_1,
        DEFAULT_KEY_2,
    };
    const int iKeysCount = 2;
    m_mca.GetMRAReader(EMraReaderId)
        ->Authenticate(nSector, KeysArray, iKeysCount, CSmartCardReader::KeyA);

    return true;
}

// Retorna o leitor lido
CMCA::EMRAReader CMraManagerImpl::GetMraReaderId() { return mraReaderId; }

// Acesso negado
void CMraManagerImpl::denyAccess(EReader eReader)
{
    CMCA::EMRAReader eMraReader = (CMCA::EMRAReader)((CMCA::ECardReader)(eReader - 16));
    m_mca.GetMRAReader(eMraReader)->accessDeny();
}

// Acesso permitido
void CMraManagerImpl::grantAccess(EReader eReader)
{
    CMCA::EMRAReader eMraReader = (CMCA::EMRAReader)((CMCA::ECardReader)(eReader - 16));
    m_mca.GetMRAReader(eMraReader)->accessGranted();
}

// Ativa modo de funcionamento normal
void CMraManagerImpl::NormalMode(CCommand *cmd)
{

    DBG_MRA("Desbloqueando Leitores MRAs...\n");
    cmd->GetDataBuffer().SetPosition(0);
    BYTE command = cmd->GetID();

    if (command == CMD_UNBLOCKDEVICE) {
        CBuffer &data = cmd->GetDataBuffer();
        UINT BlockedReaders =
            (data.GetUInt() & 0x3F0000) >> 16; // máscara e shift para pegar somente MRA's
        for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
            if ((BlockedReaders & (1 << i)) > 0 || BlockedReaders == 0x00) {
                CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                    m_mca.GetMRAReader(eReaderId)->normalMode();
                    // Informa que o dispositivo foi bloqueado devido a comando
                    // do DFS
                    m_mca.GetMRAReader(eReaderId)->SetBlockedState((EReader)eReaderId,
                                                                   false);
                }
            }
        }
    } else if (command == CMD_DEACTIVATEEMERGENCY) {
        DBG_MRA("Verifica por leitoras MRAs ativas\n");
        for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
            CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
            if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                m_mca.GetMRAReader(eReaderId)->normalMode();
                // Informa que o dispositivo foi bloqueado devido a comando do
                // DFS
                m_mca.GetMRAReader(eReaderId)->SetBlockedState((EReader)eReaderId, false);
            }
        }
    }
}

// Ativa modo de emergência
void CMraManagerImpl::EmergencyMode(void)
{
    DBG_MRA("Verifica por leitoras MRAs ativas\n");
    for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {

        CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
        if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
            m_mca.GetMRAReader(eReaderId)->emergencyMode();
        }
    }
}

// Ativa modo de bloqueio
void CMraManagerImpl::LockMode(CCommand *cmd)
{

    DBG_MRA("Bloqueando dispositivos MRAs...\n");
    CBuffer &data = cmd->GetDataBuffer();
    // Realiza a leitura do ID do comando para ajuste do buffer
    // o qual permite a leitura do dado seguinte
    cmd->GetID();

    UINT BlockedReaders = (data.GetUInt() & 0x3F0000) >> 16; // máscara para somente MRA's
    DBG_MRA("BlockedReaders %X\n", BlockedReaders);
    for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
        DBG("Mascara calculada %X\n", (BlockedReaders & (1 << i)));
        if ((BlockedReaders & (1 << i)) > 0 || BlockedReaders == 0x00) {
            CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
            DBG("Leitor a ser bloqueado %d\n", eReaderId);
            DBG("Está ativo? : %d\n", m_mca.GetMRAReader(eReaderId)->IsInitialized());
            if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                m_mca.GetMRAReader(eReaderId)->lockMode();
                // Informa que o dispositivo foi bloqueado devido a comando do
                // DFS
                m_mca.GetMRAReader(eReaderId)->SetBlockedState((EReader)eReaderId, true);
            }
        }
    }
}

// Ajuste de data e hora
void CMraManagerImpl::SetDateTimeOnMRA(CCommand *cmd)
{
    CBuffer &dataCommand = cmd->GetDataBuffer();
    if (dataCommand.Limit() == 4) {
        const UINT GMTZeroDateTime = dataCommand.GetUInt();
        if (GMTZeroDateTime) {

            // Calcula o gmt local, caso utilizar HandKey, o mesmo recebe esta
            // data;
            time_t GMTLocalDateTime = seguranca::CFirmwareUtil::GMTToLocalDateTime(
                GMTZeroDateTime, m_ctx.GetConfiguration()->GetProperties());
            for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                // Envia a data e hora recebida para cada leitra MRA ativa
                if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                    m_mca.GetMRAReader(eReaderId)->UpDateTime(GMTLocalDateTime);
                }
            }
            char cDateTime[STRDATETIMELEN];
            CFirmwareUtil::GetDateTimeString(CFirmwareUtil::GetDateTime(), cDateTime,
                                             STRDATETIMELEN);
            DBG_MRA("Data do sistema ajustada para %s %s\n", cDateTime, tzname[0]);
        } else {
            throw CCommandException(
                cmd->GetID(),
                "Erro recebendo dados do driver, data/hora zerada recebida");
        }
    } else {
        throw CCommandException(cmd->GetID(), "Erro recebendo data/hora do driver");
    }
}

// Exclui os dados de um lista inteira
bool CMraManagerImpl::RemoveAllListMRA(BYTE type, BYTE nReaderId)
{
    bool OperationStatus = false;

    // Workarandaço estilo aleixo! - FRG 30.09.13
    // MRA suporta apenas os tipo de lista 3 e 5
    // Valores diferentes destes "quebram" o fw-digicon
    if ((type != 3) && (type != 5) && (type != 4)) {
        return false;
    }

    // TODO: remover todos os templates quando tipo 4
    OperationStatus =
        m_mca.GetMRAReader((CMCA::EMRAReader)nReaderId)->RemoveListOnMRA(type);
    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

// Sincronização Biométrica
bool CMraManagerImpl::BioSync(CCommand *cmd)
{

    // Coloca msg Sincronizando no display
    if (m_ctx.CanWriteDisplay()) {
        m_ctx.GetMCA()->GetDisplay()->Write(" SINCRONIZANDO  ", "      MRAs      ");
    }

    CLock lock(m_Mutex);

    for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {

        cmd->GetDataBuffer().SetPosition(0);
        CBuffer &buff = cmd->GetDataBuffer();
        buff.GetByte(); // Omite, pois corresponde atual e exclusivamente a
                        // FingerPrint_1

        EReader eReader = (EReader)(R_MRA_1 + i);
        CMCA::EMRAReader MRAreader = (CMCA::EMRAReader)(i);

        DLOG_INFO("\n\nCOMANDO 28 para MRA[%d]\n", i);
        DLOG_INFO("MRA ativa: %s\n",
                  m_ctx.GetMCA()->GetMRAReader(MRAreader)->IsInitialized() ? "sim"
                                                                           : "nao");
        DLOG_INFO("Tecnologia biometrica: %s\n",
                  m_device.GetReaderConfig(eReader).GetManufacturer() ==
                          CBiometricReader::M_SAGEM
                      ? "Sagem"
                      : "nao");

        if (m_device.GetReaderConfig(eReader).IsActive()) {

            if (m_device.GetReaderConfig(eReader).GetManufacturer() ==
                CBiometricReader::M_SAGEM) {
                try {
                    DLOG_INFO("Iniciando parser...\n");
                    // desmancha o datagrama, e executa os comandos
                    BioSyncronize(MRAreader, buff);

                    DLOG_INFO("Parser concluido!\n");
                } catch (CCommandException &ex) {
                    DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                }
            } else if (m_device.GetReaderConfig(eReader).GetManufacturer() ==
                       CBiometricReader::M_NOT_CONFIGURED) {
                DLOG_WARNING("MRA[%d] sem tecnologia biometrica, nao recebe comando "
                             "de sincronismo biometrico!\n",
                             i);
            } else {
                DLOG_WARNING("MRA[%d] com tecnologia nao suportada para sincronismo "
                             "biometrico!\n",
                             i);
            }
        } else {
            DLOG_WARNING("MRA[%d] nao inicializada, nao recebe comando de sincronismo "
                         "biometrico!\n",
                         i);
        }
    }
    return true;
}

//-----------------------------------------------------------------------
// Este metodo efetua alteracoes no sensor de biometria e sua estrutura para
// cada MRA ativa
//-----------------------------------------------------------------------
void CMraManagerImpl::BioSyncronize(CMCA::EMRAReader MRAreader, CBuffer &buff)
{
    // quantidade de operacoes a executar
    bool faiedPersons = false;
    WORD operationsCount = buff.GetWord();
    DLOG_INFO("operacoes a executar: %d\n", operationsCount);

    BYTE operation;
    for (UINT n = 0; n < operationsCount && !m_ctx.IsFinishing(); n++) {
        // tipo de operacao
        operation = buff.GetByte();
        char PersonID[PERSONID_SIZE + 1];
        try {
            // de acordo com a operacao vai inserir ou remover
            switch (operation) {
            case 1: {
                DLOG_INFO("== OP: %d - type: %d (%s) ===\n", n + 1, operation,
                          "REFAZER/INCLUIR ESTRUTURA DE PESSOA PARA MRA");
                // remove registro da pessoa antes, se houver...
                buff.GetBytes(PersonID, PERSONID_SIZE);
                PersonID[PERSONID_SIZE] = 0;
                DLOG_INFO("remover e atualizar pessoa[%s] na MRA[%d]\n", PersonID,
                          MRAreader);

                if (m_ctx.GetMraManager()->RemovePersonOnMRA(MRAreader, PersonID,
                                                             false)) {
                    DLOG_INFO("Pessoa[%s] removida com sucesso na MRA[%d] ou nao "
                              "existente!\n",
                              PersonID, MRAreader);
                } else {
                    DLOG_ERROR("BioSyncronize: Erro excluindo pessoa "
                               "RID_MRA_%d:\nPersonID = %s\n",
                               MRAreader, PersonID);
                    char msg[512];
                    sprintf(msg, "BioSyncronize: Erro excluindo pessoa para MRA_%d!",
                            MRAreader + 1);
                    throw CCommandException(28, msg);
                }

                BYTE ListType = m_ctx.GetAuthorizedCardList()->CardListType();
                CCard Card;
                CCardCollection Cards;
                Card.SetPerson((const char *)PersonID);
                // apenas passa pelo byte de nível de conferência biométrico,
                // pois ele não é usado nas MRAs!
                BYTE ConfLevel = buff.GetByte();
                printf("Nivel de conferencia biometrico (Nao usado em MRA) %d\n",
                       ConfLevel);
                const BYTE nCardsCount = buff.GetByte();

                // sempre devera haver pelo menos um cartao, o qual eh o
                // titular, os outros serao
                // provisorios, ligados ao titular.
                printf("Quantidade de cartoes recebidos %d\n", nCardsCount);
                for (BYTE n = 0; n < nCardsCount; n++) {
                    Card.SetTecnology((CCard::ECardTecnology)buff.GetByte());
                    Card.ParseId(buff);
                    Cards.push_back(Card);
                }
                const BYTE templCount = buff.GetByte();
                int offset = 0;
                char templates[512];
                memset(templates, 0, 512);

                DBG_MRA("Preparando para enviar os templates as MRAs. QTD: [ "
                        "%d ]\n",
                        templCount);
                for (UINT n = 0; n < templCount; n++) {

                    CBiometricTemplate BioTemplate;
                    buff.GetByte();

                    WORD templSize = buff.GetWord();
                    BioTemplate.SetTemplateData(buff, templSize);

                    DBG_MRA("Tamanho do template recebido %d\n", templSize);
                    // Prepara o cabeçalho do template
                    templates[offset] = 0x02;
                    offset++;
                    templates[offset] = templSize;
                    offset++;
                    templates[offset] = (templSize >> 8);
                    offset++;
                    // Copia o template para o buffer
                    memcpy(&templates[offset], (char *)BioTemplate.GetData(), templSize);
                    offset += 170;
                }

                WORD BioId = GetRelatedBioId((char *)Card.GetPerson());

                if (UpDateListOnMRA(MRAreader, ListType, 1, Cards, BioId, templates)) {
                    // imprime log e passa adiante
                    DLOG_INFO("BioSyncronize: Enviado dados para lista de Templates "
                              "RID_MRA_%d:\nListType = %d; OperationType = 1; "
                              "PersonID = %s\n",
                              MRAreader, ListType, PersonID);
                } else {
                    // imprime log e gera exceção
                    DLOG_ERROR("BioSyncronize: Erro enviando dados da lista de "
                               "Templates RID_MRA_%d:\nListType = %d; OperationType "
                               "= 1; PersonID = %s\n",
                               MRAreader, ListType, PersonID);
                    char msg[512];
                    sprintf(msg,
                            "BioSyncronize: Erro enviando dados da lista de Templates "
                            "para MRA_%d!",
                            MRAreader + 1);
                    throw CCommandException(28, msg);
                }
            } break;
            case 2: {
                DLOG_INFO("== OP: %d - type: %d (%s) ===\n", n + 1, operation,
                          "REFAZER ESTRUTURA DE CRACHÁ PARA MRA");
                // DBG_MRA("MANTIS#2851: CARTÃO SUBSTITUTO - PONTO CORRETO")
                // remove registro da pessoa antes, se houver...
                buff.GetBytes(PersonID, PERSONID_SIZE);
                PersonID[PERSONID_SIZE] = 0;
                DLOG_INFO("remover e atualizar pessoa[%s] na MRA[%d]\n", PersonID,
                          MRAreader);

                if (m_ctx.GetMraManager()->RemovePersonOnMRA(MRAreader, PersonID, true)) {
                    DLOG_INFO("Pessoa[%s] removida com sucesso na MRA[%d] ou nao "
                              "existente!\n",
                              PersonID, MRAreader);
                } else {
                    DLOG_ERROR("BioSyncronize: Erro excluindo pessoa "
                               "RID_MRA_%d:\nPersonID = %s\n",
                               MRAreader, PersonID);
                    char msg[512];
                    sprintf(msg, "BioSyncronize: Erro excluindo pessoa para MRA_%d!",
                            MRAreader + 1);
                    throw CCommandException(28, msg);
                }

                // inclui estrutura de crachá
                BYTE ListType = m_ctx.GetAuthorizedCardList()->CardListType();
                CCard Card;
                CCardCollection Cards;
                Card.SetPerson((const char *)PersonID);

                // apenas passa pelo byte de nível de conferência biométrico,
                // pois ele não é usado nas MRAs!
                BYTE ConfLevel = buff.GetByte();
                printf("Nivel de conferencia biometrico (Nao usado em MRA) %d\n",
                       ConfLevel);

                const BYTE nCardsCount = buff.GetByte();
                DLOG_INFO("Quantidade de cartoes: %d\n", nCardsCount);
                if (nCardsCount == 0) {
                    throw CInvalidDataException(
                        "Deve haver pelo menos um cartao para a pessoa");
                }
                // sempre devera haver pelo menos um cartao, o qual eh o
                // titular, os outros serao
                // provisorios, ligados ao titular.
                for (BYTE n = 0; n < nCardsCount; n++) {
                    Card.SetTecnology((CCard::ECardTecnology)buff.GetByte());
                    Card.ParseId(buff);
                    Cards.push_back(Card);
                }
                if (UpDateListOnMRA(MRAreader, ListType, 1, 0, Cards)) {
                    // imprime log e passa adiante
                    DLOG_INFO("BioSyncronize: Enviado dados para lista de Cartoes "
                              "RID_MRA_%d:\nListType = %d; OperationType = 1; "
                              "PersonID = %s\n",
                              MRAreader, ListType, PersonID);
                } else {
                    // imprime log e gera exceção
                    DLOG_ERROR("BioSyncronize: Erro enviando dados da lista de "
                               "Cartoes RID_MRA_%d:\nListType = %d; OperationType = "
                               "1; PersonID = %s\n",
                               MRAreader, ListType, PersonID);
                    char msg[512];
                    sprintf(msg,
                            "BioSyncronize: Erro enviando dados da lista de "
                            "Cartoes para MRA_%d!",
                            MRAreader + 1);
                    throw CCommandException(28, msg);
                }
                break;
            }
            case 3: {
                DLOG_INFO("== OP: %d - type: %d (%s) ===\n", n + 1, operation,
                          "EXCLUIR ESTRUTURA DE PESSOA PARA MRA");
                // DBG_MRA("MANTIS#2851: CARTÃO SUBSTITUTO - PONTO ERRADO #2")
                // remove registro da pessoa
                buff.GetBytes(PersonID, PERSONID_SIZE);
                PersonID[PERSONID_SIZE] = 0;
                DLOG_INFO("remover pessoa[%s] na MRA[%d]\n", PersonID, MRAreader);
                if (m_ctx.GetMraManager()->RemovePersonOnMRA(MRAreader, PersonID,
                                                             false)) {
                    DLOG_INFO("Pessoa[%s] removida com sucesso na MRA[%d] ou nao "
                              "existente!\n",
                              PersonID, MRAreader);
                } else {
                    DLOG_ERROR("BioSyncronize: Erro excluindo pessoa "
                               "RID_MRA_%d:\nPersonID = %s\n",
                               MRAreader, PersonID);
                    char msg[512];
                    sprintf(msg, "BioSyncronize: Erro excluindo pessoa para MRA_%d!",
                            MRAreader + 1);
                    throw CCommandException(28, msg);
                }
                break;
            }
            default: {
                DLOG_INFO("== OP: %d - type: %d (%s) ===\n", n + 1, operation,
                          "OPERACAO INVALIDA");
                char cMessage[256];
                sprintf(cMessage, "(%d) Tipo de operacao nao suportada", operation);
                throw CInvalidDataException(cMessage);
            }
            }
        } catch (CBiometricException &ex) {
            faiedPersons = true;
        } catch (CNoMemoryException &ex) {
            faiedPersons = true;
            DLOG_ERROR("Sem espaco no sensor\n");
        } catch (CInvalidDataException &ex) {
            faiedPersons = true;
            DLOG_ERROR("Dados eviados errados\n");
        } catch (CException &ex) {
            faiedPersons = true;
            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
        }
    }
    // Comando falhou
    if (faiedPersons) {
        throw CException("Nao foi possivel atualizar todas as pessoas");
    }
}

// Atualização de Lista
void CMraManagerImpl::UpDateList(CCommand *cmd)
{

    bool fControlRemoveMra[CMCA::MAX_MRA_READERS] = {false, false, false,
                                                     false, false, false};
    CBuffer &dataCommand = cmd->GetDataBuffer();
    if (cmd->GetID() == CMD_SETLIST) // Carregamento das listas
    {
        if (m_ctx.CanWriteDisplay()) {
            m_ctx.GetMCA()->GetDisplay()->Write("BLOQUEADO CARGA ", "DE LISTA EM MRA ");
        }

        // Tipo de lista correto? 3 == lista de cartões autorizados
        // 5 == lista de cartões bloqueados
        BYTE type = dataCommand.GetByte();

        if (type == 1) // Identifica se é o tipo de lista correto, 1 == lista de
                       // permissões
        {
            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            m_Mutex.Lock();

            // testa o tamanho da lista de permissoes
            UINT DataSize = dataCommand.Remaining();
            if (DataSize > PERMISSION_MAX_SIZE) {
                char cMsg[512];
                sprintf(cMsg,
                        "(%d) Ultrapassado o limite de tamanho da lista "
                        "de permissoes! (limite:%d)",
                        DataSize, PERMISSION_MAX_SIZE);
                m_Mutex.Unlock();
                throw CInvalidDataException(cMsg);
            }
            const UINT readersCount = dataCommand.GetUInt();
            DLOG_INFO("Quantidade de leitoras: %d\n", readersCount);

            // soh pode haver o maximo de leitoras existentes
            if (readersCount > MAX_READER_CONFIGS) {
                char cMsg[512];
                sprintf(cMsg,
                        "(%d) A lista de permissoes ultrapassa o limite de leitoras!",
                        readersCount);
                m_Mutex.Unlock();
                throw CInvalidDataException(cMsg);
            }

            // monta o frame da leitora e suas permissoes
            for (UINT readerIdx = 0; readerIdx < readersCount; readerIdx++) {
                BYTE nReaderId = dataCommand.GetByte();
                UINT permsCount = dataCommand.GetUInt();

                // Testa se o leitor corresponde a um MRA
                if (nReaderId <= 16) {
                    // se não é mra, mas é uma leitora volta para o inicio do
                    // laço.
                    // e se é um indice acima de 21 não conta como indice de
                    // leitora - isso não deveria acontecer...?
                    for (UINT permIdx = 0; permIdx < permsCount; permIdx++) {
                        dataCommand.GetWord();
                        BYTE tempByte = dataCommand.GetByte();

                        for (int i = 0; i < tempByte; i++) {
                            dataCommand.GetWord();
                            dataCommand.GetWord();
                        }
                    }

                    continue;
                }
                // TODO: Rever porque no protocolo 6 aumentou o numero máximo de
                // leitoras
                CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(
                    (CMCA::MAX_MRA_READERS) - ((MAX_READER_CONFIGS) - (nReaderId - 1)));
                DLOG_INFO("[CMraManagerImpl::UpDateList] eReader %d \n", eReaderId);

                // Testa se o tipo de operação é de sobrepor. Caso verdadeiro,
                // identifica o leitor o qual o comando
                // se refere e exclui os dados da lista determinada por "type".
                if (!OperationType) {
                    // Testa se ainda não foi excluido. Caso verdadeiro exclui e
                    // marca como excluido.
                    if (fControlRemoveMra[eReaderId] == false) {
                        /*Exclui os dados da lista*/
                        // mantis#3018 - Segmentation fault
                        if (RemoveAllListMRA(type, eReaderId)) {
                            fControlRemoveMra[eReaderId] = true;
                        } else {
                            fControlRemoveMra[eReaderId] = false;
                        }
                    }
                }

                for (UINT permIdx = 0; permIdx < permsCount; permIdx++) {
                    WORD IdPermissionGroup = dataCommand.GetWord();
                    BYTE TimeIntervalCounter = dataCommand.GetByte();

                    if (TimeIntervalCounter == 0) {
                        char cMsg[512];
                        sprintf(cMsg, "A permissao %d possui dados invalidos",
                                IdPermissionGroup);
                        m_Mutex.Unlock();
                        throw CInvalidDataException(cMsg);
                    }
                    for (int i = 0; i < TimeIntervalCounter; i++) {
                        WORD start = dataCommand.GetWord();
                        WORD finish = dataCommand.GetWord();

                        try {
                            DBG_MRA("nReaderId: %d\n", nReaderId);
                            DBG_MRA("eReader %d\n", eReaderId);
                            if (eReaderId >= 0) {
                                if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                                    if (UpDateListOnMRA(eReaderId, OperationType,
                                                        IdPermissionGroup, start,
                                                        finish)) {
                                        // imprime log e passa adiante
                                        DBG_MRA("Enviado dados para lista de "
                                                "Permissões "
                                                "RID_MRA_%d:"
                                                "\nIdPermissionGroup = %d; "
                                                "Start = %d; Finish = %d\n",
                                                eReaderId, IdPermissionGroup, start,
                                                finish);
                                    } else {
                                        // imprime log e gera exceção
                                        DBG_MRA("Erro enviando dados da lista "
                                                "de Permissões "
                                                "RID_MRA_%d!"
                                                "\nIdPermissionGroup = %d; "
                                                "Start = %d; Finish = %d\n",
                                                eReaderId, IdPermissionGroup, start,
                                                finish);
                                        char msg[512];
                                        sprintf(msg,
                                                "Erro enviando dados da lista de "
                                                "Permissões para MRA_%d!",
                                                eReaderId + 1);
                                        m_Mutex.Unlock();
                                        throw CCommandException(cmd->GetID(), msg);
                                    }
                                } else {
                                    DBG_MRA("eReader no initialized %d\n", eReaderId);
                                }
                            } else {
                                DBG_MRA("Indice de leitora invalido! %d\n", eReaderId);
                            }
                        } catch (CCommandException &ex) {
                            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                        } catch (CException &ex) {
                            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                        }
                    }
                }
            }
            m_Mutex.Unlock();
            return;
        } else if (type == 2) // Identifica se é o tipo de lista correto, 2 ==
                              // lista de feriados
        {
            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            m_Mutex.Lock();

            INT ListSize = dataCommand.Remaining() / 2;

            // Carga da lista completa
            if (ListSize > 0) {
                WORD *HolidayList = new WORD[ListSize];
                for (int i = 0; i < ListSize; i++) {
                    HolidayList[i] = dataCommand.GetWord();
                    time_t StartHolidayInSeconds =
                        HolidayList[i] * SECONDS_PER_DAY; // Ajusta para a
                                                          // contagem de
                                                          // segundos do início
                                                          // do dia
                    time_t EndHolidayInSeconds =
                        (HolidayList[i] * SECONDS_PER_DAY) + SECONDS_PER_DAY -
                        1; // Ajusta para a contagem de segundos do fim do dia

                    DBG_MRA("StartHoliday %ld\n", StartHolidayInSeconds);
                    DBG_MRA("EndHoliday %ld\n", EndHolidayInSeconds);

                    for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                        CMCA::EMRAReader eReaderId =
                            (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                        try {
                            if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {

                                // Testa se o tipo de operação é de sobrepor.
                                // Caso verdadeiro, identifica o leitor o qual o
                                // comando
                                // se refere e exclui os dados da lista
                                // determinada por "type".
                                if (!OperationType) {
                                    // Testa se ainda não foi excluido. Caso
                                    // verdadeiro exclui e marca como excluido.
                                    if (fControlRemoveMra[eReaderId] == false) {
                                        /*Exclui os dados da lista*/
                                        RemoveAllListMRA(type, eReaderId);
                                        fControlRemoveMra[eReaderId] = true;
                                    }
                                }

                                if (UpDateListOnMRA(eReaderId, OperationType,
                                                    StartHolidayInSeconds,
                                                    EndHolidayInSeconds)) {
                                    // imprime log e passa adiante
                                    DLOG_INFO("Enviado dados para lista de Feriados "
                                              "RID_MRA_%d:\nHolidayList[%d] = %d; "
                                              "OperationType = %d; "
                                              "StartHolidayInSeconds = %ld; "
                                              "EndHolidayInSeconds = %ld;\n",
                                              eReaderId, i, HolidayList[i], OperationType,
                                              StartHolidayInSeconds, EndHolidayInSeconds);
                                } else {
                                    // imprime log e gera exceção
                                    DLOG_ERROR("Erro enviando dados da lista de "
                                               "Feriados "
                                               "RID_MRA_%d!\nHolidayList[%d] = %d; "
                                               "OperationType = %d; "
                                               "StartHolidayInSeconds = %ld; "
                                               "EndHolidayInSeconds = %ld;\n",
                                               eReaderId, i, HolidayList[i],
                                               OperationType, StartHolidayInSeconds,
                                               EndHolidayInSeconds);
                                    char msg[512];
                                    sprintf(msg,
                                            "Erro enviando dados da lista de Feriados "
                                            "para MRA_%d!",
                                            eReaderId + 1);
                                    m_Mutex.Unlock();
                                    throw CCommandException(cmd->GetID(), msg);
                                }
                            }
                        } catch (CCommandException &ex) {
                            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                        } catch (CException &ex) {
                            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                        }
                    }
                }
                delete[] HolidayList;
            }
            m_Mutex.Unlock();
            return;
        } else if (type == 3 || type == 5) {
            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            if (dataCommand.Remaining() % CAuthorizedCardList::CardNode::SizeOf !=
                0) // Checa o tamanho dos dados
            {
                throw CCommandException(cmd->GetID(),
                                        "O tamanho da lista de cartões é invalido");
            }

            char cMessage[256];
            INT listSize = dataCommand.Remaining();

            int numbOfNodes = listSize / CAuthorizedCardList::CardNode::SizeOf;

            BYTE ListType = m_ctx.GetAuthorizedCardList()->CardListType();

            if ((type == 3 && ListType == CAuthorizedCardList::unauthorizedList) ||
                (type == 5 && ListType == CAuthorizedCardList::authorizedList)) {
                if (OperationType != 0) {
                    sprintf(cMessage, "Recebeu lista de %s e esperava lista de %s",
                            (type == 3) ? "acesso" : "bloqueio",
                            (ListType == CAuthorizedCardList::authorizedList)
                                ? "acesso"
                                : "bloqueio");
                    throw CCommandException(cmd->GetID(), cMessage);
                }
            } else if (type != 3 && type != 5) { // TODO tratar este caso!
                //				ListType = (type == 3)?
                //(CAuthorizedCardList::authorizedList):(CAuthorizedCardList::unauthorizedList);
                sprintf(cMessage, "Comando de carga de uma lista inválida!");
                throw CCommandException(cmd->GetID(), cMessage);
            }

            if (OperationType == 0 || OperationType == 2) {
                if (listSize > MAX_LIST_SIZE) // Ultrapassa o tamanho limite
                {
                    sprintf(cMessage,
                            "A lista possui %d bytes, quantidade maxima aceita: %d",
                            listSize, MAX_LIST_SIZE);
                    throw CCommandException(cmd->GetID(), cMessage);
                }
            } else if (OperationType == 1) {
                if ((listSize + numbOfNodes * CAuthorizedCardList::CardNode::SizeOf) >
                    MAX_LIST_SIZE) // Ultrapassa o tamanho limite
                {
                    sprintf(cMessage,
                            "A lista possui %d bytes, quantidade maxima aceita: %d",
                            listSize,
                            MAX_LIST_SIZE -
                                (numbOfNodes * CAuthorizedCardList::CardNode::SizeOf));
                    throw CCommandException(cmd->GetID(), cMessage);
                }
            }

            // m_Mutex.Lock();

            for (int i = 0; i < numbOfNodes; i++) {
                CCard Card;
                CCardCollection Cards;
                Card.ParseId(dataCommand);
                Cards.push_back(Card);

                UINT EnabledReaders =
                    dataCommand.GetUInt();             // Coleta as leitoras respondentes
                BYTE CardType = dataCommand.GetByte(); // Coleta o tipo de
                                                       // cartão (Mestre,
                                                       // empregado, aluno..)

                // Envia os dados parseados para as MRAs
                for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                    CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                    try {
                        // Testa se o MRA foi inicializado
                        if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                            // Verifica se o tipo de operação é de exlusão ou
                            // sobreposição. Caso verdadeiro considera a máscara
                            // "EnableReaders"
                            // para identificar o leitor correto a receber o
                            // cadastro.

                            DBG_MRA("OperationType: %d\n", OperationType);
                            DBG_MRA("Check ENABLE: %d\n",
                                    CHECK_MRA_ENABLED(EnabledReaders, (BYTE)eReaderId));

                            if ((OperationType < 2) &&
                                (CHECK_MRA_ENABLED(EnabledReaders, (BYTE)eReaderId))) {
                                // Testa se o tipo de operação é de sobrepor.
                                // Caso verdadeiro, identifica o leitor o qual o
                                // comando
                                // se refere e exclui os dados da lista
                                // determinada por "type".
                                if (!OperationType) {
                                    // Testa se ainda não foi excluido. Caso
                                    // verdadeiro exclui e marca como excluido.
                                    if (fControlRemoveMra[eReaderId] == false) {
                                        /*Exclui os dados da lista*/
                                        RemoveAllListMRA(type, eReaderId);
                                        fControlRemoveMra[eReaderId] = true;
                                    }
                                }
                                if (UpDateListOnMRA(eReaderId, type, OperationType,
                                                    CardType, Cards)) {
                                    // imprime log e passa adiante
                                    DLOG_INFO("Enviado dados para lista de "
                                              "Acesso/Bloqueio RID_MRA_%d\n",
                                              eReaderId);
                                } else {
                                    // imprime log e gera exceção
                                    DLOG_ERROR("Erro enviando dados da lista de "
                                               "Acesso/Bloqueio RID_MRA_%d!\n",
                                               eReaderId);
                                    char msg[512];
                                    sprintf(msg,
                                            "Erro enviando dados da lista de "
                                            "Acesso/Bloqueio para MRA_%d!",
                                            eReaderId + 1);
                                    // m_Mutex.Unlock();
                                    throw CCommandException(cmd->GetID(), msg);
                                }
                                // Testa se o tipo de operação é de exclusão
                            } else if ((OperationType == 2) ||
                                       (((OperationType == 1) || (OperationType == 0)) &&
                                        (!CHECK_MRA_ENABLED(EnabledReaders,
                                                            (BYTE)eReaderId)))) {
                                if (UpDateListOnMRA(eReaderId, ListType, 2, 0, Cards)) {
                                    // imprime log e passa adiante
                                    DLOG_INFO("Enviado dados para exclusao da lista "
                                              "de Acesso/Bloqueio RID_MRA_%d\n",
                                              eReaderId);
                                } else {
                                    // imprime log e gera exceção
                                    DLOG_ERROR("Erro enviando dados para exclusao da "
                                               "lista de Acesso/Bloqueio "
                                               "RID_MRA_%d!\n",
                                               eReaderId);
                                    char msg[512];
                                    sprintf(msg,
                                            "Erro enviando dados da lista de "
                                            "Acesso/Bloqueio para MRA_%d!",
                                            eReaderId + 1);
                                    // m_Mutex.Unlock();
                                    throw CCommandException(cmd->GetID(), msg);
                                }
                            }
                        }
                    } catch (CCommandException &ex) {
                        DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                    } catch (CException &ex) {
                        DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                    }
                }
            }
            // m_Mutex.Unlock();
            return;
        } else if (type == 4) // Lista de templates biometricos
        {
            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            BYTE ListType = m_ctx.GetAuthorizedCardList()->CardListType();

            m_Mutex.Lock();

            WORD personsCount = dataCommand.GetWord();
            DLOG_INFO("Quantidade de pessoas recebida para envio nas MRAs: %d\n",
                      personsCount);

            // Workarandaço estilo Aleixo para resolver a questão da exclusao de
            // biometrias
            // quando enviado o comando 5(Carga de Lista) com Tipo de Lista = 4
            // e Tipo de
            // Operacao = 0 sem nenhuma estrutura de cartao

            DBG_MRA("personsCount: %d\n", personsCount);
            DBG_MRA("OperationType: %d\n", OperationType);
            if ((!personsCount) && (!OperationType)) {
                for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                    CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                    if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                        try {
                            DBG_MRA("eReaderId: %d\n", eReaderId);
                            RemoveAllListMRA(0x04, eReaderId);
                        } catch (CCommandException &ex) {
                            DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                        }
                    } else {
                        DBG_MRA("MRA INDICE %d NAO INICIALIZADA!\n", eReaderId);
                    }
                }
                DLOG_INFO("PARSE DO COMANDO PARA MRAs CONCLUIDO\n");
                m_Mutex.Unlock();
                return;
            }

            for (WORD w = 0; w < personsCount; w++) {
                BYTE PersonID[PERSONID_SIZE];
                CCard Card;
                CCardCollection Cards;
                dataCommand.GetBytes(PersonID, PERSONID_SIZE);
                Card.SetPerson((const char *)PersonID);
                // apenas passa pelo byte de nível de conferência biométrico,
                // pois ele não é usado nas MRAs!
                dataCommand.GetByte();
                const BYTE nCardsCount = dataCommand.GetByte();

                // sempre devera haver pelo menos um cartao, o qual eh o
                // titular, os outros serao
                // provisorios, ligados ao titular.
                printf("Quantidade de cartoes recebidos %d\n", nCardsCount);
                for (BYTE n = 0; n < nCardsCount; n++) {
                    Card.SetTecnology((CCard::ECardTecnology)dataCommand.GetByte());
                    Card.ParseId(dataCommand);
                    Cards.push_back(Card);
                }
                const BYTE templCount = dataCommand.GetByte();
                int offset = 0;
                char templates[512];
                memset(templates, 0, 512);

                DBG_MRA("Preparando para enviar os templates as MRAs. QTD: [ "
                        "%d ]\n",
                        templCount);
                for (UINT n = 0; n < templCount; n++) {

                    CBiometricTemplate BioTemplate;
                    dataCommand.GetByte();

                    WORD templSize = dataCommand.GetWord();
                    BioTemplate.SetTemplateData(dataCommand, templSize);

                    DBG_MRA("Tamanho do template recebido %d\n", templSize);
                    // Prepara o cabeçalho do template
                    templates[offset] = 0x02;
                    offset++;
                    templates[offset] = templSize;
                    offset++;
                    templates[offset] = (templSize >> 8);
                    offset++;
                    // Copia o template para o buffer
                    memcpy(&templates[offset], (char *)BioTemplate.GetData(), templSize);
                    offset += 170;
                }
                WORD BioId = GetRelatedBioId((char *)Card.GetPerson());

                for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                    CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                    try {
                        // Envia o template recebido para cada dispositivo MRA
                        // ativo
                        if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                            // Testa se o tipo de operação é de sobrepor. Caso
                            // verdadeiro, identifica o leitor o qual o comando
                            // se refere e exclui os dados da lista determinada
                            // por "type".
                            if (!OperationType) {
                                // Testa se ainda não foi excluido. Caso
                                // verdadeiro exclui e marca como excluido.
                                if (fControlRemoveMra[eReaderId] == false) {
                                    /*Exclui os dados da lista*/
                                    RemoveAllListMRA(type, eReaderId);
                                    fControlRemoveMra[eReaderId] = true;
                                }
                            }
                            if (UpDateListOnMRA(eReaderId, ListType, OperationType, Cards,
                                                BioId, templates)) {
                                // imprime log e passa adiante
                                DLOG_INFO("Enviado dados para lista de Templates "
                                          "RID_MRA_%d:\nListType = %d; "
                                          "OperationType = %d; PersonID = %s\n",
                                          eReaderId, ListType, OperationType, PersonID);
                            } else {
                                // imprime log e gera exceção
                                DLOG_ERROR("Erro enviando dados da lista de "
                                           "Templates RID_MRA_%d:\nListType = %d; "
                                           "OperationType = %d; PersonID = %s\n",
                                           eReaderId, ListType, OperationType, PersonID);
                                char msg[512];
                                sprintf(msg,
                                        "Erro enviando dados da lista de Templates para "
                                        "MRA_%d!",
                                        eReaderId + 1);
                                m_Mutex.Unlock();
                                throw CCommandException(cmd->GetID(), msg);
                            }
                        }
                    } catch (CCommandException &ex) {
                        DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                    } catch (CException &ex) {
                        DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                    }
                }
            }
            DLOG_INFO("PARSE DO COMANDO PARA MRAs CONCLUIDO\n");
            m_Mutex.Unlock();
            return;
        } else if (type == 6) { // Lista de pessoas/empregados

            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            BYTE ListType = m_ctx.GetAuthorizedCardList()->CardListType();

            // quantidade de pessoas
            WORD wPersonsCount = dataCommand.GetWord();
            // conta a quantidade de cartoes recebidos na lista
            UINT CardCount = 0;

            DLOG_INFO("Inicializado envio da lista para MRAs\n");

            m_Mutex.Lock();

            CCardCollection Cards;

            for (WORD w = 0; w < wPersonsCount; w++) {
                CCard Card;
                BYTE PersonID[PERSONID_SIZE];

                dataCommand.GetBytes(PersonID, PERSONID_SIZE);
                Card.SetPerson((const char *)PersonID);
                // apenas passa pelo byte de nível de conferência biométrico,
                // pois ele não é usado nas MRAs!
                dataCommand.GetByte();
                const BYTE nCardsCount = dataCommand.GetByte();
                DLOG_INFO("Quantidade de cartoes: %d\n", nCardsCount);
                if (nCardsCount == 0) {
                    m_Mutex.Unlock();
                    throw CInvalidDataException(
                        "Deve haver pelo menos um cartao para a pessoa");
                }
                // sempre devera haver pelo menos um cartao, o qual eh o
                // titular, os outros serao
                // provisorios, ligados ao titular.
                for (BYTE n = 0; n < nCardsCount; n++) {
                    Card.SetTecnology((CCard::ECardTecnology)dataCommand.GetByte());
                    Card.ParseId(dataCommand);
                    Cards.push_back(Card);
                }
            }

            // Envia para as MRAs os dados parseados
            for (int i = 0; i < CMCA::MAX_MRA_READERS; i++) {
                CMCA::EMRAReader eReaderId = (CMCA::EMRAReader)(CMCA::RID_MRA_1 + i);
                try {
                    // Envia o cartão recebido para cada dispositivo MRA ativo
                    if (m_mca.GetMRAReader(eReaderId)->IsInitialized()) {
                        // Testa se o tipo de operação é de sobrepor. Caso
                        // verdadeiro, identifica o leitor o qual o comando
                        // se refere e exclui os dados da lista determinada por
                        // "type".
                        if (!OperationType) {
                            // Testa se ainda não foi excluido. Caso verdadeiro
                            // exclui e marca como excluido.
                            if (fControlRemoveMra[eReaderId] == false) {
                                /*Exclui os dados da lista*/
                                RemoveAllListMRA(type, eReaderId);
                                fControlRemoveMra[eReaderId] = true;
                            }
                        }
                        if (UpDateListOnMRA(eReaderId, ListType, OperationType, 0,
                                            Cards)) {
                            // imprime log e passa adiante
                            DLOG_INFO("Enviado dados para lista de Registro de "
                                      "Empregados RID_MRA_%d:\nListType = %d; "
                                      "OperationType = %d\n",
                                      eReaderId, ListType, OperationType);
                        } else {
                            // imprime log e gera exceção
                            DLOG_ERROR("Erro enviando dados da lista de Registro de "
                                       "Empregados RID_MRA_%d:\nListType = %d; "
                                       "OperationType = %d\n",
                                       eReaderId, ListType, OperationType);
                            char msg[512];
                            sprintf(msg,
                                    "Erro enviando dados da lista de Registro de "
                                    "Empregados para MRA_%d!",
                                    eReaderId + 1);
                            m_Mutex.Unlock();
                            throw CCommandException(cmd->GetID(), msg);
                        }
                    }
                } catch (CCommandException &ex) {
                    DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                } catch (CException &ex) {
                    DLOG_ERROR("Erro: %s\n", ex.GetMessage());
                }
            }
            m_Mutex.Unlock();

            CPersonManager pManage(m_ctx);
            if (CardCount > pManage.GetCountPeople()) {
                throw CCommandException(cmd->GetID(),
                                        "Lista de pessoas ultrapassa a "
                                        "quantidade maxima de 15000 cartoes");
            }
            return;
        }
    }
}

bool CMraManagerImpl::GetPersonFromFinger(char *personId)
{
    bool bResult = false;
    if (m_readerOp.m_wIdOverModule) {
        // m_wIdOverModule foi previamente lido em HasFinger
        if (m_FingerLinks->FindRelatedPerson(m_readerOp.m_wIdOverModule, personId)) {
            DBG_MRA("1:N - Pessoa: \"%s\"", personId);
            bResult = true;
        } else {
            DLOG_WARNING("Id:%d - Digital existente, mas nao relacionada com um cartao. "
                         "NAO DEVERIA ACONTECER ISTO\n",
                         m_readerOp.m_wIdOverModule);
        }
    }
    return bResult;
}

WORD CMraManagerImpl::GetRelatedBioId(char *personId)
{
    return m_FingerLinks->FindRelatedBioId(personId);
}

CMraManager::EMRAManagerType CMraManagerImpl::GetMraManagerType() { return BT_NONE; }

bool CMraManagerImpl::UpDateListOnMRA(CMCA::EMRAReader MRAreader, BYTE OpType,
                                      WORD IdPermGroup, time_t StartInt, time_t EndInt)
{

    bool OperationStatus = false;

    OperationStatus = m_mca.GetMRAReader(MRAreader)->UpDate_PermissionList(
        OpType, IdPermGroup, StartInt, EndInt);

    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

bool CMraManagerImpl::UpDateListOnMRA(CMCA::EMRAReader MRAreader, BYTE OpType,
                                      time_t StartTimeSt, time_t EndTimeSt)
{

    bool OperationStatus = false;

    OperationStatus =
        m_mca.GetMRAReader(MRAreader)->UpDate_HolidayList(OpType, StartTimeSt, EndTimeSt);

    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

bool CMraManagerImpl::UpDateListOnMRA(CMCA::EMRAReader MRAreader, BYTE ListType,
                                      BYTE OpType, BYTE CardType, CCardCollection &Cards)
{

    bool OperationStatus = false;

    if (ListType == 3) {
        OperationStatus = m_mca.GetMRAReader(MRAreader)->UpDate_AccessList(
            OpType, Cards.at(0).GetId(), CardType);
    } else if (ListType == 5) {
        OperationStatus = m_mca.GetMRAReader(MRAreader)->UpDate_BlockList(
            OpType, Cards.at(0).GetId(), CardType);
    } else if (ListType == CAuthorizedCardList::authorizedList) {
        OperationStatus =
            m_mca.GetMRAReader(MRAreader)->UpDate_REAccessList(OpType, Cards);
    } else if (ListType == CAuthorizedCardList::unauthorizedList) {
        OperationStatus =
            m_mca.GetMRAReader(MRAreader)->UpDate_REBlockList(OpType, Cards);
    }

    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

bool CMraManagerImpl::UpDateListOnMRA(CMCA::EMRAReader MRAreader, BYTE ListType,
                                      BYTE OpType, CCardCollection &Cards, WORD bioId,
                                      char *FingerPrints)
{

    bool OperationStatus = false;

    if (ListType == CAuthorizedCardList::authorizedList) {
        OperationStatus = m_mca.GetMRAReader(MRAreader)->UpDate_BioAccessList(
            OpType, Cards, bioId, FingerPrints);
    } else if (ListType == CAuthorizedCardList::unauthorizedList) {
        OperationStatus = m_mca.GetMRAReader(MRAreader)->UpDate_BioBlockList(
            OpType, Cards, bioId, FingerPrints);
    }

    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

bool CMraManagerImpl::RemovePersonOnMRA(CMCA::EMRAReader MRAreader, char *PersonID,
                                        bool KeepBio)
{

    bool OperationStatus = false;

    OperationStatus = m_mca.GetMRAReader(MRAreader)->Remove_Person(PersonID, KeepBio);

    if (OperationStatus) {
        return true;
    } else {
        return false;
    }
}

bool CMraManagerImpl::HandleCommand(CCommand &Command, CReturn &Return)
{

    // Thread is running ?
    if (m_ctx.GetMRAImpl()->GetIsRunning()) {

        bool bExecuteHandler = false;
        for (BYTE i = 0; i < CMCA::MAX_MRA_READERS; i++) {
            if (m_mca.GetMRAReader((CMCA::EMRAReader)(CMCA::RID_MRA_1 + i))
                    ->IsInitialized())
                bExecuteHandler = true;
        }

        if (!bExecuteHandler) {
            return false;
        }

        m_ctx.GetMRAImpl()->pausePolling();
        try {
            switch (Command.GetID()) {
            // Carregar lista
            case CMD_SETLIST:
                UpDateList(&Command);
                break;
            // Atualizar Relógiol
            case CMD_SETDATETIME:
                SetDateTimeOnMRA(&Command);
                break;
            // Bloqueio e desbloqueio do controlador
            case CMD_BLOCKDEVICE:
                LockMode(&Command);
                break;
            case CMD_UNBLOCKDEVICE:
                NormalMode(&Command);
                break;
            // Retorna do modo de emergência para o modo de funcionamento normal
            case CMD_DEACTIVATEEMERGENCY:
                NormalMode(&Command);
                break;
            // Ativa o modo de emergencia
            case CMD_ACTIVATEEMERGENCY:
                EmergencyMode();
                break;
            // Estado das saídas digitais
            case CMD_GETOUTPUTSTATUS: /*Reservado para uso futuro*/
                break;
            // Estado das entradas digitais
            case CMD_GETINPUTSTATUS: /*Reservado para uso futuro*/
                break;
            // Comando de sincronização biométrica
            case CMD_BIOSYNCRONIZE: {
                bool bio = BioSync(&Command);
                m_ctx.GetMRAImpl()->resumePolling();
                return bio;
            }
            default:
                // Se nao foi mapeado no switch,
                // informa que esta classe nao é
                // responsável por tratar esse comando.
                m_ctx.GetMRAImpl()->resumePolling();
                return false;
            };

        } catch (...) {
            DLOG_ERROR("[CMraManagerImpl] Relancando excecao.\n");
            m_ctx.GetMRAImpl()->resumePolling();
            throw;
        }
    }

    DLOG_INFO("[CMraManagerImpl]Comando executado com sucesso.\n");
    m_ctx.GetMRAImpl()->resumePolling();
    return true;
}

} /* namespace seguranca */

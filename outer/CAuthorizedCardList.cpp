#include "CAuthorizedCardList.h"
#include "CCommand.h"
#include "CReturn.h"
#include "CInvalidDataException.h"
#include "CFileException.h"
#include "CStreamFactory.h"
#include "CFirmwareUtil.h"
#include "CStream.h"
#include "CDevice.h"
#include <memory.h>
#include <stdlib.h>
#include <sys/stat.h>

#define AUTHORIZEDCARDLIST_FILENAME "authorizedcards.dat"

using base::CStream;
using base::CInvalidDataException;
using base::CFileException;
using base::CStreamFactory;

namespace seguranca
{

CAuthorizedCardList::CAuthorizedCardList(CContext &Ctx, CDevice &Device)
    : m_Device(Device), m_Ctx(Ctx),
      m_Stream(CStreamFactory::GetStream(AUTHORIZEDCARDLIST_FILENAME))
{
    m_ListType = authorizedList;
    m_pCarList = NULL;
    m_ListSize = 0;
    Load();
}

CAuthorizedCardList::~CAuthorizedCardList() { SAFE_DELETE_ARRAY(m_pCarList); }

void CAuthorizedCardList::Load()
{
    try {
        m_Stream.Open();
        m_Stream.ReadAllContent();
        if (m_Stream.Remaining() == 0) {
            return;
        }

        m_Stream.GetWord();
        m_ListType = (eCardListType)m_Stream.GetByte();
        m_ListSize = (m_Stream.Remaining()) /
                     CardNode::SizeOf; // Desconsidera o WORD da versão do
                                       // arquivo e o BYTE do tipo da lista
        SAFE_DELETE_ARRAY(m_pCarList);
        m_pCarList = new CardNode[m_ListSize];

        for (int i = 0; i < m_ListSize; i++) {
            m_pCarList[i].Read(m_Stream);
        }
    } catch (const CFileException &ex) {
        DLOG_ERROR("!!!!  Erro abrindo arquivo de cartões autorizados ---- NÃO "
                   "DEVERIA ACONTECER ISTO  !!!!\n");
    }
}

void CAuthorizedCardList::InitFile()
{
    try {
        m_Stream.SetStreamPosition(0);
        m_Stream.PutWord(FILE_SYSTEM_VERSION);
        m_Stream.PutByte(m_ListType);
    } catch (const CFileException &ex) {
        DLOG_ERROR("!!!!  Erro inicializando arquivo de cartões autorizados ---- NÃO "
                   "DEVERIA ACONTECER ISTO  !!!!\n");
    }
}

void CAuthorizedCardList::SaveCards(size_t firstIndex, int cardCount, CardNode *cardNodes)
{
    try {
        m_Stream.Open();

        size_t offset = firstIndex * CardNode::SizeOf + 3;
        if (offset == m_Stream.GetSize()) {
            size_t newSize = m_Stream.GetSize() + cardCount * CardNode::SizeOf;
            m_Stream.SetSize(newSize);
        }
        m_Stream.SetStreamPosition(offset);

        for (int i = 0; i < cardCount; i++) {
            cardNodes->Write(m_Stream);
            cardNodes++;
            m_Stream.WriteBlock();
        }
    } catch (const CFileException &ex) {
        DLOG_ERROR("!!!!  Erro salvando no arquivo de cartões autorizados ---- NÃO "
                   "DEVERIA ACONTECER ISTO  !!!!\n");
    }
}

void CAuthorizedCardList::SaveAll()
{
    CStreamOpener opener(m_Stream);
    m_Stream.ForceLimit(m_ListSize * CardNode::SizeOf + 3);

    InitFile();

    for (int i = 0; i < m_ListSize; i++) {
        m_pCarList[i].Write(m_Stream);
    }
    m_Stream.WriteAllContent();
}

bool CAuthorizedCardList::Contains(digicon::CCard Card, EReader eReader, BYTE &CardType)
{
    ULONGLONG llID;
    CardType = CReaderConfig::NONE;
    bool bResult = (CardListType() == authorizedList) ? false : true;
    m_Mutex.Lock();
    // Caso fique lento, pode-se ordenar na gravação da lista e fazer pesquisa
    // binaria
    for (int i = 0; i < m_ListSize; i++) {
        llID = digicon::CCard::MakeLL(m_pCarList[i].pCardID);
        if (llID == Card.GetId()) {
            CardType = m_pCarList[i].CardType;
            bResult = (m_pCarList[i].EnabledReaders & (1 << eReader)) > 0;
            break;
        }
    }
    m_Mutex.Unlock();
    return bResult;
}

bool CAuthorizedCardList::LogicalIDContains(ULONGLONG LogicalNumber, EReader eReader,
                                            BYTE &CardType)
{
    ULONGLONG llID;
    CardType = CReaderConfig::NONE;
    bool bResult = (CardListType() == authorizedList) ? false : true;
    m_Mutex.Lock();
    // Caso fique lento, pode-se ordenar na gravação da lista e fazer pesquisa
    // binaria
    for (int i = 0; i < m_ListSize; i++) {
        llID = digicon::CCard::MakeLL(m_pCarList[i].pCardID);

        if (llID == LogicalNumber) {
            CardType = m_pCarList[i].CardType;
            bResult = (m_pCarList[i].EnabledReaders & (1 << eReader)) > 0;

            break;
        }
    }
    m_Mutex.Unlock();
    return bResult;
}

bool CAuthorizedCardList::HandleCommand(CCommand &Command, CReturn &Return)
{
    CBuffer &dataCommand = Command.GetDataBuffer();
    if (Command.GetID() == CMD_SETLIST) // Carregamento das listas
    {
        if (m_Ctx.CanWriteDisplay()) {
            m_Ctx.GetMCA()->GetDisplay()->Write("   BLOQUEADO    ", " CARGA DE LISTA ");
        }

        // Tipo de lista correto? 3 == lista de cartões autorizados
        //						  5 == lista de cartões
        // bloqueados
        BYTE type = dataCommand.GetByte();
        if (type == 3 || type == 5) {
            // Tipo de operação: 0 == lista completa; 1 == incluir cadastros; 2
            // == excluir cadastros
            BYTE OperationType = dataCommand.GetByte();

            if (dataCommand.Remaining() % CardNode::SizeOf !=
                0) // Checa o tamanho dos dados
            {
                throw CCommandException(Command.GetID(),
                                        "O tamanho da lista de cartões é invalido");
            }

            char cMessage[256];
            INT listSize = dataCommand.Remaining();

            // Carga da lista completa
            if (OperationType == 0) {
                if (listSize > MAX_LIST_SIZE) // Ultrapassa o tamanho limite
                {
                    sprintf(cMessage,
                            "A lista possui %d bytes, quantidade maxima aceita: %d",
                            listSize, MAX_LIST_SIZE);
                    throw CCommandException(Command.GetID(), cMessage);
                }

                m_Mutex.Lock();
                m_ListSize = listSize / CardNode::SizeOf;
                SAFE_DELETE_ARRAY(m_pCarList);
                m_pCarList = new CardNode[m_ListSize];
                m_ListType = authorizedList;
                if (type == 5) // Lista de bloqueio
                {
                    m_ListType = unauthorizedList;
                }

                for (int i = 0; i < m_ListSize; i++) {
                    dataCommand.GetBytes(m_pCarList[i].pCardID, 5);
                    m_pCarList[i].EnabledReaders = dataCommand.GetUInt();
                    m_pCarList[i].CardType = dataCommand.GetByte();
                }

                SaveAll();

                // inclusão de cadastros na lista
            } else if (OperationType == 1) {
                if ((listSize + m_ListSize * CardNode::SizeOf) >
                    MAX_LIST_SIZE) // Ultrapassa o tamanho limite
                {
                    sprintf(cMessage,
                            "A lista possui %d bytes, quantidade maxima aceita: %d",
                            listSize, MAX_LIST_SIZE - (m_ListSize * CardNode::SizeOf));
                    throw CCommandException(Command.GetID(), cMessage);
                }

                if (((type == 3) && (m_ListType == unauthorizedList)) ||
                    ((type == 5) && (m_ListType == authorizedList))) {
                    sprintf(cMessage, "Recebeu lista de %s e esperava lista de %s",
                            (type == 3) ? "acesso" : "bloqueio",
                            (m_ListType == authorizedList) ? "acesso" : "bloqueio");
                    throw CCommandException(Command.GetID(), cMessage);
                }

                m_Mutex.Lock();

                CStreamOpener opener(m_Stream);
                if (m_Stream.GetSize() < 3) {
                    InitFile();
                    m_Stream.WriteBlock();
                }

                // Carrega os cadastros recebidos
                listSize = listSize / CardNode::SizeOf;
                CardNode *pCarListNew = new CardNode[listSize];
                for (int i = 0; i < listSize; i++) {
                    dataCommand.GetBytes(pCarListNew[i].pCardID, 5);
                    pCarListNew[i].EnabledReaders = dataCommand.GetUInt();
                    pCarListNew[i].CardType = dataCommand.GetByte();
                    for (int j = 0; j < m_ListSize; j++) {
                        // Caso o cadastro já existe na lista, atualiza as
                        // configurações do mesmo.
                        if (digicon::CCard::MakeLL(m_pCarList[j].pCardID) ==
                            digicon::CCard::MakeLL(pCarListNew[i].pCardID)) {
                            m_pCarList[j].EnabledReaders = pCarListNew[i].EnabledReaders;
                            m_pCarList[j].CardType = pCarListNew[i].CardType;
                            i--;
                            listSize--;

                            // salva modificação no arquivo
                            SaveCards(j, 1, &m_pCarList[j]);
                            break;
                        }
                    }
                }

                // Cria backup da lista antiga
                CardNode *pCarListOld = new CardNode[m_ListSize];
                for (int i = 0; i < m_ListSize; i++) {
                    memcpy(pCarListOld[i].pCardID, m_pCarList[i].pCardID, 5);
                    pCarListOld[i].EnabledReaders = m_pCarList[i].EnabledReaders;
                    pCarListOld[i].CardType = m_pCarList[i].CardType;
                }

                // Carrega os cadastros da lista atual na nova lista
                SAFE_DELETE_ARRAY(m_pCarList);
                m_pCarList = new CardNode[m_ListSize + listSize];
                for (int i = 0; i < m_ListSize; i++) {
                    memcpy(m_pCarList[i].pCardID, pCarListOld[i].pCardID, 5);
                    m_pCarList[i].EnabledReaders = pCarListOld[i].EnabledReaders;
                    m_pCarList[i].CardType = pCarListOld[i].CardType;
                }

                // Carrega os novos cadastros na nova lista
                SAFE_DELETE_ARRAY(pCarListOld);
                for (int i = m_ListSize; i < (m_ListSize + listSize); i++) {
                    memcpy(m_pCarList[i].pCardID, pCarListNew[i - m_ListSize].pCardID, 5);
                    m_pCarList[i].EnabledReaders =
                        pCarListNew[i - m_ListSize].EnabledReaders;
                    m_pCarList[i].CardType = pCarListNew[i - m_ListSize].CardType;
                }

                // salva novos cadastros no final do arquivo
                if (listSize > 0) {
                    SaveCards(m_ListSize, listSize, pCarListNew);
                }

                m_ListSize = m_ListSize + listSize;

                // Exclui cadastros da lista
            } else if (OperationType == 2) {
                if (listSize > MAX_LIST_SIZE) // Ultrapassa o tamanho limite
                {
                    sprintf(cMessage,
                            "A lista possui %d bytes, quantidade maxima aceita: %d",
                            listSize, MAX_LIST_SIZE);
                    throw CCommandException(Command.GetID(), cMessage);
                }

                if (((type == 3) && (m_ListType == unauthorizedList)) ||
                    ((type == 5) && (m_ListType == authorizedList))) {
                    sprintf(cMessage, "Recebeu lista de %s e esperava lista de %s",
                            (type == 3) ? "acesso" : "bloqueio",
                            (m_ListType == authorizedList) ? "acesso" : "bloqueio");
                    throw CCommandException(Command.GetID(), cMessage);
                }

                m_Mutex.Lock();

                // Carrega os cadastros recebidos
                listSize = listSize / CardNode::SizeOf;
                CardNode *pCarListNew = new CardNode[listSize];
                for (int i = 0; i < listSize; i++) {
                    dataCommand.GetBytes(pCarListNew[i].pCardID, 5);
                    pCarListNew[i].EnabledReaders = dataCommand.GetUInt();
                    pCarListNew[i].CardType = dataCommand.GetByte();
                    // Remove registro da lista
                    RemoveRegister(digicon::CCard::MakeLL(pCarListNew[i].pCardID),
                                   m_ListType);
                }
                SAFE_DELETE_ARRAY(pCarListNew);
            }

            m_Mutex.Unlock();
            return true;
        }
    } else if (Command.GetID() == CMD_EXCLUDELIST) // Exclusão da lista
    {
        // Tipo de lista correto? 3 == lista de cartões autorizados
        //						  5 == lista de cartões
        // bloqueados
        BYTE type = dataCommand.GetByte();
        if (type == 3 || type == 5) {
            m_Mutex.Lock();
            SAFE_DELETE_ARRAY(m_pCarList);
            m_ListSize = 0;
            SaveAll();
            m_Mutex.Unlock();
            return true;
        }
    } else if (Command.GetID() ==
               CMD_GETLISTSTATUS) // Status da lista de cartões autorizados
    {
        // Tipo de lista correto? 3 == lista de cartões autorizados
        //						  5 == lista de cartões
        // bloqueados
        BYTE type = dataCommand.GetByte();
        if (type == 3 || type == 5) {
            struct stat FileStat;
            memset(&FileStat, 0, sizeof(FileStat));
            stat(AUTHORIZEDCARDLIST_FILENAME, &FileStat);

            CBuffer &dataReturn = Return.Data();
            dataReturn.PutWord(m_ListSize);
            dataReturn.PutUInt(FileStat.st_size);
            dataReturn.PutUInt((m_ListType == authorizedList) ? 3 : 5);
            UINT lastModification = (UINT)CFirmwareUtil::GMTToLocalDateTime(
                FileStat.st_mtime, m_Ctx.GetConfiguration()->GetProperties());
            dataReturn.PutUInt(lastModification);
            return true;
        }
    }
    return false;
}

void CAuthorizedCardList::RemoveRegister(ULONGLONG CardID, eCardListType ListType)
{
    if (m_ListType == ListType) {
        for (int i = 0; i < m_ListSize; i++) {
            // Caso encontre o cadastro na lista, substitui pelo último da
            // lista.
            if (digicon::CCard::MakeLL(m_pCarList[i].pCardID) == CardID) {
                m_ListSize--;
                memcpy(m_pCarList[i].pCardID, m_pCarList[m_ListSize].pCardID, 5);
                memset(m_pCarList[m_ListSize].pCardID, 0, 5);
                m_pCarList[i].EnabledReaders = m_pCarList[m_ListSize].EnabledReaders;
                m_pCarList[i].CardType = m_pCarList[m_ListSize].CardType;

                // salva essa exclusão no arquivo
                SaveCards(i, 1, &m_pCarList[i]);
                size_t newSize = m_Stream.GetSize() - CardNode::SizeOf;
                m_Stream.SetSize(newSize);

                break;
            }
        }
    }
}

CAuthorizedCardList::eCardListType CAuthorizedCardList::CardListType()
{
    return m_ListType;
}

bool CAuthorizedCardList::MasterCardContains(digicon::CCard Card, EReader eReader)
{
    ULONGLONG llID;
    BYTE CardType = CReaderConfig::MASTER_CARD;

    bool bIsAuthorizedList = (CardListType() == authorizedList) ? true : false;
    bool bResult = false;
    m_Mutex.Lock();
    // Caso fique lento, pode-se ordenar na gravação da lista e fazer pesquisa
    // binaria
    for (int i = 0; i < m_ListSize; i++) {
        llID = digicon::CCard::MakeLL(m_pCarList[i].pCardID);

        if (llID == Card.GetId()) {
            if ((CardType == (1 << ((m_pCarList[i].CardType & 0x0F) - 1))) &&
                bIsAuthorizedList) {
                bResult = true;
                DLOG_INFO("Cartao Mestre encontrado na lista de cartoes "
                          "autorizados!\n");
            } else if ((CardType == (1 << ((m_pCarList[i].CardType & 0x0F) - 1))) &&
                       !bIsAuthorizedList) {
                bResult = false;
                DLOG_INFO("Cartao Mestre encontrado na lista de cartoes "
                          "bloqueados!\n");
            }
            break;
        }
    }
    m_Mutex.Unlock();
    return bResult;
}
}

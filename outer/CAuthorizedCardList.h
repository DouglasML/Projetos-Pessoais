#ifndef CAUTHORIZEDCARDLIST_H_
#define CAUTHORIZEDCARDLIST_H_

#include "CCommandHandler.h"
#include "CMutex.h"
#include "CCard.h"
#include "CBuffer.h"
#include "ConfigConstants.h"
#include "CContext.h"

#define MAX_LIST_SIZE 614400 // Tamanho máximo da lista 600Kb (76800 cartoes)

namespace base
{
class CStream;
};

namespace seguranca
{

class CDevice;

/* Classe CAuthorizedCardList
 * Gerencia uma lista serializada de catões e as leitoras que estes cartões
 *têm/não têm acesso
 *
 */
class CAuthorizedCardList : public CCommandHandler
{
  public:
    // Tipo da lista de cartões
    enum eCardListType {
        authorizedList = 0,  // lista de cartões autorizados
        unauthorizedList = 1 // lista de cartões bloqueados
    };

    // Estrutura contendo numero do cartão e leitoras habilitadas
    struct CardNode
    {
        BYTE pCardID[5];
        UINT EnabledReaders;
        BYTE CardType;

        static const size_t SizeOf = 5 + 4 + 1;

        void Write(CBuffer &data) const
        {
            data.PutBytes(pCardID, 5);
            data.PutInt(EnabledReaders);
            data.PutByte(CardType);
        }

        void Read(CBuffer &data)
        {
            data.GetBytes(pCardID, 5);
            EnabledReaders = data.GetInt();
            CardType = data.GetByte();
        }
    };

    inline CardNode *GetListAccess() { return m_pCarList; }

  private:
    // Carrega a lista de cartões no disco
    void Load();

    // Abre arquivo e o inicializa caso não tenha sido inicializado
    void InitFile();

    // Grava toda a lista de cartões no arquivo, sobrescrevendo-o
    void SaveAll();

    // Grava cartões a partir de uma determinada posição do arquivo
    void SaveCards(size_t firstIndex, int cardCount, CardNode *cardNodes);

    base::CMutex m_Mutex;
    CardNode *m_pCarList;
    int m_ListSize;
    eCardListType m_ListType;

    // variavel adicionada para consulta do GMT
    CDevice &m_Device;
    CContext &m_Ctx;

    base::CStream &m_Stream;

  public:
    CAuthorizedCardList(CContext &Ctx, CDevice &Device);
    virtual ~CAuthorizedCardList();

    // Tratador dos comandos de carga e exclusão da lista de cartões
    virtual bool HandleCommand(CCommand &Command, CReturn &Return);

    // Verifica se um cartão está autorizado/bloqueado para uma leitora
    bool Contains(digicon::CCard Card, EReader eReader, BYTE &CardType);

    // Verifica se um número lógico informado está autorizado/bloqueado para uma
    // leitora
    bool LogicalIDContains(ULONGLONG LogicalNumber, EReader eReader, BYTE &CardType);

    // Exclui registro da lista
    void RemoveRegister(ULONGLONG CardID, eCardListType ListType);

    // Verifica se um cartão é mestre na lista de autorizados
    bool MasterCardContains(digicon::CCard Card, EReader eReader);

    // Retorna se a lista é de cartões autorizados/bloqueados
    CAuthorizedCardList::eCardListType CardListType();

    inline UINT GetSize() { return m_ListSize; }

    inline CardNode *ReturnList() { return m_pCarList; }
};
}

#endif /*CAUTHORIZEDCARDLIST_H_*/

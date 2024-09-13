import { SearchDatabase, SearchPayload } from '../interfaces/global-interface'

export class Global {
  public includeParamsRelations(query: string | undefined) {
    const relations = query?.split(',')

    if (!relations || relations.length == 0) return {}

    let params = {}

    relations.forEach((relation) => {
      if (relation.includes('.')) {
        const linkedRelations = relation.split('.')
        if (linkedRelations[1].includes('*')) {
          // ! O formato pode vir desta maneira user.city*state
          const nestedRelations = linkedRelations[1].split('*')
          let include = {}

          nestedRelations.forEach((nestedRelation) => {
            // ! O trecho pode repetir mais de 2 vezes, então com esse foreach ele vai formatar no formato do objeto que o prisma precisa
            // ! Por exemplo: {city: true, state: true}
            include = {
              ...include,
              [nestedRelation]: true,
            }
          })

          params = {
            ...params,
            [linkedRelations[0]]: {
              include,
            },
          }
        } else {
          params = {
            ...params,
            [linkedRelations[0]]: {
              include: {
                [linkedRelations[1]]: true,
              },
            },
          }
        }
      } else {
        params = { ...params, [relation]: true }
      }
    })

    return { include: params }
  }

  public generateFilters(payload: SearchPayload): SearchDatabase {
    let params = {}
    let search = null

    if (payload.search) {
      let searchKey = {}
      const searchObject = Object.keys(payload.search).map((key) => {
        let searchKeyFormatted: string | undefined = undefined
        if (payload.options?.search === 'equals') {
          search = (payload.search as any)[key]
        } else {
          search = { contains: (payload.search as any)[key] }
        }

        // ! Verifica se o último caractere é digito para receber multiplos indexes iguais
        if (/^\d+(?:\.\d+)?$/.test(key.charAt(key.length - 1))) {
          searchKeyFormatted = key.slice(0, -1)
        }

        if (typeof (payload.search as any)[key] !== 'string') {
          if (key.includes('.')) {
            const linkedKeys = key.split('.')
            searchKey = this.generateSearchKey(
              linkedKeys,
              searchKeyFormatted,
              key,
              payload.search,
              payload.options?.search || 'contains'
            )
          } else {
            searchKey = {
              [searchKeyFormatted || key]: (payload.search as any)[key],
            }
          }
        } else {
          if (key.includes('.')) {
            const linkedKeys = key.split('.')
            searchKey = this.generateSearchKey(
              linkedKeys,
              searchKeyFormatted,
              key,
              payload.search,
              payload.options?.search || 'contains'
            )
          } else {
            searchKey = {
              [searchKeyFormatted || key]: search,
            }
          }
        }

        return searchKey
      })

      params = { where: { [payload.options?.filter || 'OR']: searchObject } }
    }

    let orderBy: Array<Object> = []
    if (payload.sort) {
      Object.keys(payload.sort).forEach((sortField) => {
        if (sortField.includes('.')) {
          const linkedSortFields = sortField.split('.')

          orderBy.push({
            [linkedSortFields[0]]: {
              [linkedSortFields[1]]: (payload.sort as any)[sortField],
            },
          })
        } else {
          orderBy.push({
            [sortField]: (payload.sort as any)[sortField],
          })
        }
      })
    }

    params = {
      ...params,
      orderBy,
    }

    if (payload.pagination)
      params = {
        ...params,
        take: payload.pagination.take,
        skip: payload.pagination.take * (payload.pagination.page - 1),
      }

    return params
  }

  private generateSearchKey(
    linkedKeys: Array<string>,
    searchKeyFormatted: string | undefined,
    key: string,
    search: Object,
    options: string
  ) {
    let relationToSearch = undefined

    // ! Search depth on relations
    if (linkedKeys[2]) {
      // ! Options defines if the search is about the exatcly same string or just containing the letter on their string similar to %%
      if (options === 'equals') {
        relationToSearch = {
          [searchKeyFormatted || linkedKeys[2]]: (search as any)[key],
        }
      } else {
        relationToSearch = {
          [searchKeyFormatted || linkedKeys[2]]: {
            contains: (search as any)[key],
          },
        }
      }
    } else {
      // ! Options defines if the search is about the exatcly same string or just containing the letter on their string similar to %%
      if (options === 'equals') {
        relationToSearch = (search as any)[key]
      } else {
        relationToSearch = { contains: (search as any)[key] }
      }
    }

    return {
      [linkedKeys[0]]: {
        [linkedKeys[1]]: relationToSearch,
      },
    }
  }
}

export interface SearchPayload {
  search?: {} | any
  sort?: {}
  options?: {
    filter?: 'AND' | 'OR'
    search?: 'contains' | 'equals'
  }
  pagination?: { page: number; take: number }
  includes?: string
}

export interface SearchGetPayload {
  page?: string
  take?: string
}

export interface SearchDatabase {
  where?: {
    OR?: Array<{}>
    AND?: Array<{}>
  }
  orderBy?: {}
  take?: number
  skip?: number
}

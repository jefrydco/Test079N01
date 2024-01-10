import { createConnection, getConnection, getRepository } from 'typeorm'
import dataSourceOptions from 'src/database/data-source'

export function setupBeforeAndAfter() {
  beforeAll(async () => {
    return createConnection({
      ...dataSourceOptions,
    })
  })

  beforeEach(async () => {
    const entities = getConnection().entityMetadatas
    for (const entity of entities) {
      const repository = await getConnection().getRepository(entity.name)
      await repository.query(`TRUNCATE ${entity.tableName} RESTART IDENTITY CASCADE;`)
    }
  })

  afterAll(() => {
    const conn = getConnection()
    return conn.close()
  })
}

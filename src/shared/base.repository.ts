import {
  Brackets,
  Repository,
  DeepPartial,
  ObjectLiteral,
  SelectQueryBuilder,
  WhereExpressionBuilder,
  QueryRunner,
} from 'typeorm';
import { NotFoundException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { DEFAULT_PAGE_NUMBER, DEFAULT_PAGE_SIZE } from '@constants/index';

type ClassType<T> = {
  new (...args: unknown[]): T;
};

export enum QueryOperators {
  START_WITH = 'START_WITH',
  END_WITH = 'END_WITH',
  CONTAINS = 'CONTAINS',
  CONTAIN = 'CONTAIN',
  LIKE = 'LIKE',
  NOT_EQUAL = 'NOT_EQUAL',
  EQUAL = 'EQUAL',
  GREATER_THAN = 'GREATER_THAN',
  LESS_THAN = 'LESS_THAN',
  GREATER_THAN_OR_EQUAL = 'GREATER_THAN_OR_EQUAL',
  GREATER_OR_EQUAL_THAN = 'GREATER_OR_EQUAL_THAN',
  LESS_OR_EQUAL_THAN = 'LESS_OR_EQUAL_THAN',
  LESS_THAN_OR_EQUAL = 'LESS_THAN_OR_EQUAL',
  IN = 'IN',
  NOT_IN = 'NOT_IN',
  BETWEEN = 'BETWEEN',
}

export enum QueryWhereType {
  WHERE = 'WHERE',
  WHERE_AND = 'WHERE_AND',
  WHERE_OR = 'WHERE_OR',
}

export enum QueryOrderDir {
  ASC = 'ASC',
  DESC = 'DESC',
}

export type CondtionItem = {
  whereType: QueryWhereType;
  column?: string;
  value?: unknown;
  operator?: QueryOperators;
  paramName?: string; // use for relation condition
  conditions?: QueryCondition[];
  builder?: ConditionFunction;
};
export type ConditionFunction = (value: WhereExpressionBuilder) => WhereExpressionBuilder;
export type QueryCondition = CondtionItem | ConditionFunction;

export type QueryPagination = {
  page: number;
  limit: number;
};

export type QueryOrder = {
  orderBy: string;
  orderDir: QueryOrderDir;
};

export type QueryRelation = {
  column: string;
  alias: string;
  order?: QueryOrder;
  joinType?: 'left' | 'inner' | 'count';
  joinCondition?: CondtionItem;
};

export class BaseRepository<T> extends Repository<T> {
  protected get alias(): string {
    return this.metadata.tableName;
  }

  protected get primaryFields(): string[] {
    return this.metadata.primaryColumns.map((column) => column.propertyName);
  }

  protected get entityType(): ClassType<T> {
    return this.target as ClassType<T>;
  }

  public async findMany(
    params: {
      conditions?: QueryCondition[];
      relations?: QueryRelation[];
      pagination?: QueryPagination;
      orders?: QueryOrder[];
    },
    queryRunner?: QueryRunner,
  ): Promise<[T[], number, number]> {
    const { conditions, relations, pagination, orders } = params;

    const queryBuilder = this.createQueryBuilder(this.alias, queryRunner);

    if (conditions?.length > 0) {
      this._buildConditionQuery(queryBuilder, conditions);
    }

    if (relations?.length > 0) {
      this._buildRelationQuery(queryBuilder, relations);
    }

    queryBuilder.skip(
      ((pagination.page || DEFAULT_PAGE_NUMBER) - 1) * (pagination.limit || DEFAULT_PAGE_SIZE),
    );
    queryBuilder.take(pagination.limit || DEFAULT_PAGE_SIZE);

    if (orders) {
      orders.forEach((order, index) => {
        if (index === 0) {
          queryBuilder.orderBy(`${this._parseColumnName(order.orderBy)}`, order.orderDir);
        } else {
          queryBuilder.addOrderBy(`${this._parseColumnName(order.orderBy)}`, order.orderDir);
        }
      });
    }

    const [records, total] = await queryBuilder.getManyAndCount();

    const totalPage = this._getTotalPages(total, pagination.limit || DEFAULT_PAGE_SIZE);

    return [records, total, totalPage];
  }

  async getOne(
    params: { conditions?: QueryCondition[]; relations?: QueryRelation[] },
    queryRunner?: QueryRunner,
  ) {
    const { conditions, relations } = params;
    const queryBuilder = this.createQueryBuilder(this.alias, queryRunner);

    if (conditions?.length > 0) {
      this._buildConditionQuery(queryBuilder, conditions);
    }

    if (relations?.length > 0) {
      this._buildRelationQuery(queryBuilder, relations);
    }

    const entity = await queryBuilder.getOne();

    if (!entity) {
      throw new NotFoundException();
    }

    return entity;
  }

  async getRelations(entity: T, options: { relations: QueryRelation[] }) {
    const newConditions: QueryCondition[] = this.primaryFields.map((field) => {
      return {
        column: field,
        value: entity[field],
        operator: QueryOperators.EQUAL,
        whereType: QueryWhereType.WHERE_AND,
      };
    });

    return this.getOne({
      conditions: newConditions,
      relations: options.relations,
    });
  }

  async createOne(params: { data: DeepPartial<T> }, queryRunner?: QueryRunner) {
    const { data } = params;

    const entity = plainToInstance(this.entityType, data);

    return queryRunner?.manager
      ? queryRunner?.manager?.save(entity, { transaction: false })
      : this.save(entity);
  }

  async updateOne(
    params: {
      conditions: QueryCondition[];
      data: DeepPartial<T>;
    },
    queryRunner?: QueryRunner,
  ): Promise<T> {
    const { conditions, data } = params;

    const entity = await this.getOne({ conditions }, queryRunner);

    const updateData = this.merge(entity, data);

    return queryRunner?.manager ? queryRunner?.manager.save(updateData) : this.save(updateData);
  }

  async removeOne(params: { conditions: QueryCondition[] }, queryRunner?: QueryRunner): Promise<T> {
    const { conditions } = params;

    const entity = await this.getOne({ conditions }, queryRunner);

    return queryRunner?.manager ? queryRunner?.manager.remove(entity) : this.remove(entity);
  }

  private _getTotalPages(totalRecords: number, limit: number) {
    const totalPages = totalRecords / limit;
    const remainder = totalRecords % limit;
    return remainder > 0 ? Math.floor(totalPages) + 1 : totalPages;
  }

  private _buildConditionQuery(queryBuilder: WhereExpressionBuilder, conditions: QueryCondition[]) {
    conditions.forEach((condition, index) => {
      if (typeof condition === 'function') {
        return condition(queryBuilder);
      }

      const {
        whereType,
        column,
        value,
        operator,
        builder,
        conditions: childConditions,
      } = condition;

      if (builder) {
        return this._buildWhereType(queryBuilder, {
          whereType,
          where: builder,
        });
      }
      if (childConditions) {
        return this._buildWhereType(queryBuilder, {
          whereType,
          where: new Brackets((qb) => {
            this._buildConditionQuery(qb, childConditions);
          }),
        });
      }

      let statement;
      let params;
      if (value === undefined || value === null || !column) return;

      const columnName = this._parseColumnName(column);
      const paramName = this._parseParamName(column);
      if (Array.isArray(value) && [QueryOperators.IN, QueryOperators.NOT_IN].includes(operator)) {
        statement = [
          columnName,
          this._parseOperator(operator),
          `(${this._toBindingArray(paramName)})`,
        ];
        params = { [paramName]: value };
      } else if (Array.isArray(value) && [QueryOperators.BETWEEN].includes(operator)) {
        const fromParamKey = `${paramName}_${index}_from`;
        const toParamKey = `${paramName}_${index}_to`;
        statement = [
          columnName,
          this._parseOperator(operator),
          this._toBindingVariable(fromParamKey),
          'AND',
          this._toBindingVariable(toParamKey),
        ];
        params = {
          [fromParamKey]: value[0],
          [toParamKey]: value[1],
        };
      } else {
        statement = [columnName, this._parseOperator(operator), this._toBindingVariable(paramName)];
        params = {
          [paramName]: this._parseParameter(value, operator),
        };
      }

      return this._buildWhereType(queryBuilder, {
        whereType,
        where: statement.join(' '),
        params,
      });
    });
  }

  private _buildWhereType(
    queryBuilder: WhereExpressionBuilder,
    options: {
      whereType: QueryWhereType;
      where?:
        | string
        | Brackets
        | ((qb: WhereExpressionBuilder) => string)
        | ObjectLiteral
        | ObjectLiteral[];
      params?: ObjectLiteral;
    },
  ) {
    if (!options.where) {
      throw new Error('Missing conditions');
    }
    // TODO: something wrong with typescript in query builder type
    const where: unknown = options.where;
    switch (options.whereType) {
      case QueryWhereType.WHERE:
        queryBuilder.where(where, options.params);
        break;
      case QueryWhereType.WHERE_AND:
        queryBuilder.andWhere(where, options.params);
        break;
      case QueryWhereType.WHERE_OR:
        queryBuilder.orWhere(where, options.params);
        break;
      default:
        throw new Error('Unsupported where type');
    }
    return queryBuilder;
  }

  private _buildJoinCondition(joinCondition?: CondtionItem) {
    return joinCondition
      ? [
          `${joinCondition?.column}${this._parseOperator(joinCondition.operator)}${
            joinCondition.value
          }`,
        ]
      : [];
  }

  private _buildRelationQuery(queryBuilder: SelectQueryBuilder<T>, relations: QueryRelation[]) {
    relations.forEach(({ column, alias, joinType, joinCondition, order }) => {
      switch (joinType) {
        case 'count':
          queryBuilder.loadRelationCountAndMap(
            this._parseColumnName(alias),
            this._parseColumnName(column),
            alias,
          );
          break;
        case 'inner':
          queryBuilder.innerJoinAndSelect(
            `${this._parseColumnName(column)}`,
            alias,
            ...this._buildJoinCondition(joinCondition),
          );
          break;
        default:
          queryBuilder.leftJoinAndSelect(
            `${this._parseColumnName(column)}`,
            alias,
            ...this._buildJoinCondition(joinCondition),
          );
          break;
      }
      if (order) {
        queryBuilder.orderBy(`${this._parseColumnName(order.orderBy)}`, order.orderDir);
      }
    });
  }

  private _parseOperator(operator: QueryOperators) {
    switch (operator) {
      case QueryOperators.START_WITH:
      case QueryOperators.END_WITH:
      case QueryOperators.CONTAINS:
      case QueryOperators.CONTAIN:
      case QueryOperators.LIKE:
        return 'LIKE';
      case QueryOperators.GREATER_THAN_OR_EQUAL:
      case QueryOperators.GREATER_OR_EQUAL_THAN:
        return '>=';
      case QueryOperators.GREATER_THAN:
        return '>';
      case QueryOperators.LESS_THAN_OR_EQUAL:
      case QueryOperators.LESS_OR_EQUAL_THAN:
        return '<=';
      case QueryOperators.LESS_THAN:
        return '<';
      case QueryOperators.NOT_EQUAL:
        return '!=';
      case QueryOperators.BETWEEN:
        return 'BETWEEN';
      default:
        return '=';
    }
  }

  private _parseParameter(value: unknown, operator: QueryOperators) {
    switch (operator) {
      case QueryOperators.START_WITH:
        return `${value}%`;
      case QueryOperators.END_WITH:
        return `%${value}`;
      case QueryOperators.CONTAINS:
      case QueryOperators.CONTAIN:
        return `%${value}%`;
      default:
        return value;
    }
  }

  private _parseColumnName(name: string) {
    return name.includes('.') ? name : `${this.alias}.${name}`;
  }

  private _parseParamName(name: string) {
    return name.includes('.') ? name.split('.').pop() : name;
  }

  private _toBindingVariable(name: string) {
    return `:${name}`;
  }

  private _toBindingArray(name: string) {
    return `:...${name}`;
  }
}

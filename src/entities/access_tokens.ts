import {
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  Index,
} from 'typeorm';

@Entity('access_tokens')
export class AccessToken {
  @PrimaryGeneratedColumn()
  @Column({ type: 'integer', primary: true })
  id: number;

  @Index({ unique: true })
  @Column({ nullable: false, type: 'varchar' })
  token: string;

  @Index()
  @Column({ nullable: false, type: 'varchar' })
  refresh_token: string;

  @Column({ nullable: false, type: 'integer' })
  resource_owner_id: number;

  @Column({ nullable: false, type: 'varchar' })
  resource_owner_type: string;

  @Column({ nullable: true, type: 'timestamp' })
  @CreateDateColumn()
  created_at: Date;

  @Column({ nullable: true, type: 'timestamp' })
  @UpdateDateColumn()
  updated_at: Date;
}

import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('storage_files')
export class StorageFile {
  @PrimaryGeneratedColumn()
  @Column({ type: 'integer', primary: true })
  id: number;

  @Column({ nullable: false, type: 'varchar' })
  file_path: string;

  @Column({ nullable: false, type: 'varchar' })
  origin_name: string;

  @Column({ nullable: false, type: 'varchar' })
  mime_type: string;

  @Column({ nullable: false, type: 'varchar' })
  checksum: string;

  @Column({ nullable: false, type: 'integer' })
  size: number;

  @Column({ nullable: false, type: 'varchar' })
  disk: string;

  @Column({ nullable: true, type: 'integer' })
  uploader_id?: number;

  // Virtual column
  url: string;

  @Column({ nullable: true, type: 'timestamp' })
  @CreateDateColumn()
  created_at: Date;

  @Column({ nullable: true, type: 'timestamp' })
  @CreateDateColumn()
  updated_at: Date;
}

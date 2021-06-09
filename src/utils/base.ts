import dotenv from 'dotenv';

dotenv.config();

export function getDomain(): string {
  return `http://${process.env.HOST}:${process.env.PORT}`;
}

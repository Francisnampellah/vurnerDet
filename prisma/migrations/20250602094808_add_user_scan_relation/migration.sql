/*
  Warnings:

  - Added the required column `userId` to the `ScanSession` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "ScanSession" ADD COLUMN     "userId" TEXT NOT NULL;

-- CreateIndex
CREATE INDEX "ScanSession_userId_idx" ON "ScanSession"("userId");

-- AddForeignKey
ALTER TABLE "ScanSession" ADD CONSTRAINT "ScanSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

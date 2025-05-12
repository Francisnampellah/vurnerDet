/*
  Warnings:

  - The primary key for the `ScanSession` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `activeScanAlerts` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `completedAt` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `notes` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `spiderResults` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `startedAt` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `status` on the `ScanSession` table. All the data in the column will be lost.
  - You are about to drop the column `targetUrl` on the `ScanSession` table. All the data in the column will be lost.
  - The `id` column on the `ScanSession` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - Added the required column `url` to the `ScanSession` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "ScanSession" DROP CONSTRAINT "ScanSession_pkey",
DROP COLUMN "activeScanAlerts",
DROP COLUMN "completedAt",
DROP COLUMN "notes",
DROP COLUMN "spiderResults",
DROP COLUMN "startedAt",
DROP COLUMN "status",
DROP COLUMN "targetUrl",
ADD COLUMN     "activeId" TEXT,
ADD COLUMN     "activeStatus" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "spiderId" TEXT,
ADD COLUMN     "spiderStatus" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "url" TEXT NOT NULL,
DROP COLUMN "id",
ADD COLUMN     "id" SERIAL NOT NULL,
ADD CONSTRAINT "ScanSession_pkey" PRIMARY KEY ("id");

-- AlterTable
ALTER TABLE "ScanSession" ADD COLUMN     "authenticationMethod" TEXT,
ADD COLUMN     "ipAddress" TEXT,
ADD COLUMN     "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "technologies" JSONB,
ADD COLUMN     "webServer" TEXT;

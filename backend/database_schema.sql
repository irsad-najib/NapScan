-- Database Schema for NapScan
-- Generated based on GORM models

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for users
-- Source: backend/internal/models/auth.go
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` varchar(191) NOT NULL,
  `email` varchar(191) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `picture` text,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for schedules
-- Source: backend/internal/models/schedule.go
-- ----------------------------
DROP TABLE IF EXISTS `schedules`;
CREATE TABLE `schedules` (
  `id` char(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `target` varchar(255) NOT NULL,
  `tool` varchar(50) NOT NULL,
  `cron_expression` varchar(50) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `last_run` datetime(3) DEFAULT NULL,
  `last_run_status` varchar(20) DEFAULT NULL,
  `last_resource_id` varchar(255) DEFAULT NULL,
  `next_run` datetime(3) DEFAULT NULL,
  `user_id` char(36) NOT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_schedules_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for batches
-- Source: backend/internal/models/batch.go
-- ----------------------------
DROP TABLE IF EXISTS `batches`;
CREATE TABLE `batches` (
  `batch_id` varchar(191) NOT NULL,
  `user_id` varchar(191) DEFAULT NULL,
  `expected_count` bigint DEFAULT NULL,
  `received_count` bigint DEFAULT NULL,
  `results` longtext,
  `status` varchar(32) DEFAULT NULL,
  `report_path` varchar(512) DEFAULT NULL,
  `analysis_result` longtext,
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`batch_id`),
  KEY `idx_batches_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for scan_results
-- Source: backend/internal/models/scan_result.go
-- ----------------------------
DROP TABLE IF EXISTS `scan_results`;
CREATE TABLE `scan_results` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `batch_id` varchar(191) DEFAULT NULL,
  `tool` varchar(64) DEFAULT NULL,
  `target` varchar(255) DEFAULT NULL,
  `result` longtext,
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_scan_results_batch_id` (`batch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for uploaded_files
-- Source: backend/internal/models/lifecycle.go
-- ----------------------------
DROP TABLE IF EXISTS `uploaded_files`;
CREATE TABLE `uploaded_files` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `batch_id` varchar(191) DEFAULT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `file_path` varchar(512) DEFAULT NULL,
  `hash` varchar(64) DEFAULT NULL,
  `status` varchar(32) DEFAULT 'UPLOADED',
  `severity_score` varchar(16) DEFAULT NULL,
  `findings_summary` text,
  `error_message` text,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_uploaded_files_batch_id` (`batch_id`),
  KEY `idx_uploaded_files_hash` (`hash`),
  KEY `idx_uploaded_files_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

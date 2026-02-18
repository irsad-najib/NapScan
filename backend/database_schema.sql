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

-- ----------------------------
-- Table structure for cwe_definitions
-- Source: backend/internal/models/cwe.go
-- ----------------------------
DROP TABLE IF EXISTS `cwe_definitions`;
CREATE TABLE `cwe_definitions` (
  `cwe_id` varchar(64) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `description` text,
  `abstraction` varchar(64) DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`cwe_id`),
  KEY `idx_cwe_definitions_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for cve_cache
-- Source: backend/internal/models/cve.go
-- ----------------------------
DROP TABLE IF EXISTS `cve_cache`;
CREATE TABLE `cve_cache` (
  `cve_id` varchar(64) NOT NULL,
  `cwe_id` varchar(64) DEFAULT NULL,
  `cvss_score` decimal(4,1) DEFAULT NULL,
  `cvss_vector` varchar(255) DEFAULT NULL,
  `severity` varchar(32) DEFAULT NULL,
  `description` text,
  `published_at` datetime(3) DEFAULT NULL,
  `last_synced` datetime(3) DEFAULT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`cve_id`),
  KEY `idx_cve_cache_cwe_id` (`cwe_id`),
  KEY `idx_cve_cache_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for cpe_definitions
-- Source: backend/internal/models/cpe.go
-- ----------------------------
DROP TABLE IF EXISTS `cpe_definitions`;
CREATE TABLE `cpe_definitions` (
  `cpe_uri` varchar(255) NOT NULL,
  `vendor` varchar(128) DEFAULT NULL,
  `product` varchar(128) DEFAULT NULL,
  `version` varchar(64) DEFAULT NULL,
  `part` char(1) DEFAULT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`cpe_uri`),
  KEY `idx_cpe_definitions_vendor` (`vendor`),
  KEY `idx_cpe_definitions_product` (`product`),
  KEY `idx_cpe_definitions_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for vulnerability_profiles
-- Source: backend/internal/models/finding.go
-- ----------------------------
DROP TABLE IF EXISTS `vulnerability_profiles`;
CREATE TABLE `vulnerability_profiles` (
  `internal_code` varchar(128) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `cwe_id` varchar(64) DEFAULT NULL,
  `default_cvss_vector` varchar(255) DEFAULT NULL,
  `default_cvss_score` decimal(4,1) DEFAULT NULL,
  `severity` varchar(32) DEFAULT NULL,
  `description` text,
  `recommendation` text,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`internal_code`),
  KEY `idx_vulnerability_profiles_cwe_id` (`cwe_id`),
  KEY `idx_vulnerability_profiles_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------
-- Table structure for detected_findings
-- Source: backend/internal/models/finding.go
-- ----------------------------
DROP TABLE IF EXISTS `detected_findings`;
CREATE TABLE `detected_findings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `scan_id` varchar(191) DEFAULT NULL,
  `tenant_id` varchar(191) DEFAULT NULL,
  `vuln_type` varchar(32) DEFAULT NULL,
  `reference_id` varchar(255) DEFAULT NULL,
  `cvss_score` decimal(4,1) DEFAULT NULL,
  `cvss_vector` varchar(255) DEFAULT NULL,
  `severity` varchar(32) DEFAULT NULL,
  `raw_data` longtext,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_detected_findings_scan_id` (`scan_id`),
  KEY `idx_detected_findings_tenant_id` (`tenant_id`),
  KEY `idx_detected_findings_vuln_type` (`vuln_type`),
  KEY `idx_detected_findings_reference_id` (`reference_id`),
  KEY `idx_detected_findings_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

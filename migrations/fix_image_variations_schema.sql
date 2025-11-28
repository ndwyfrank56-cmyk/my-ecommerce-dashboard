-- Migration: Add missing columns to image_variations table if they don't exist
-- This fixes the "Unknown column 'name' in 'field list'" error

-- Check and add 'name' column if missing
ALTER TABLE `image_variations` 
ADD COLUMN `name` VARCHAR(100) NOT NULL DEFAULT 'Variation' AFTER `type`;

-- Check and add 'description' column if missing  
ALTER TABLE `image_variations`
ADD COLUMN `description` VARCHAR(1000) DEFAULT NULL AFTER `name`;

-- Check and add 'img_url' column if missing
ALTER TABLE `image_variations`
ADD COLUMN `img_url` VARCHAR(255) NOT NULL DEFAULT '' AFTER `stock`;

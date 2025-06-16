package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quantumca-platform/internal/utils"
)

type BackupService struct {
	config *utils.Config
	logger *utils.Logger
	ticker *time.Ticker
	stopCh chan struct{}
}

func NewBackupService(config *utils.Config, logger *utils.Logger) *BackupService {
	return &BackupService{
		config: config,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

func (s *BackupService) Start() error {
	if !s.config.BackupEnabled {
		s.logger.Info("Backup service disabled")
		return nil
	}

	s.ticker = time.NewTicker(s.config.BackupInterval)
	go func() {
		s.logger.Info("Backup service started")
		for {
			select {
			case <-s.ticker.C:
				if err := s.CreateBackup(); err != nil {
					s.logger.LogError(err, "Backup failed", nil)
				}
			case <-s.stopCh:
				return
			}
		}
	}()

	return nil
}

func (s *BackupService) Stop() error {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.stopCh)
	s.logger.Info("Backup service stopped")
	return nil
}

func (s *BackupService) CreateBackup() error {
	timestamp := time.Now().Format("20060102_150405")
	backupDir := filepath.Join("./backups", timestamp)
	
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	s.logger.Infof("Creating backup in %s", backupDir)

	if err := s.backupDatabase(backupDir); err != nil {
		return fmt.Errorf("failed to backup database: %w", err)
	}

	if err := s.backupKeys(backupDir); err != nil {
		return fmt.Errorf("failed to backup keys: %w", err)
	}

	if err := s.backupCertificates(backupDir); err != nil {
		return fmt.Errorf("failed to backup certificates: %w", err)
	}

	if err := s.cleanupOldBackups(); err != nil {
		s.logger.Warnf("Failed to cleanup old backups: %v", err)
	}

	s.logger.Infof("Backup completed successfully: %s", backupDir)
	return nil
}

func (s *BackupService) backupDatabase(backupDir string) error {
	srcPath := s.config.DatabasePath
	dstPath := filepath.Join(backupDir, "database.db")
	
	return s.copyFile(srcPath, dstPath)
}

func (s *BackupService) backupKeys(backupDir string) error {
	keysBackupDir := filepath.Join(backupDir, "keys")
	if err := os.MkdirAll(keysBackupDir, 0700); err != nil {
		return err
	}

	return filepath.Walk(s.config.KeysPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(s.config.KeysPath, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(keysBackupDir, relPath)
		dstDir := filepath.Dir(dstPath)
		
		if err := os.MkdirAll(dstDir, 0700); err != nil {
			return err
		}

		return s.copyFile(path, dstPath)
	})
}

func (s *BackupService) backupCertificates(backupDir string) error {
	certsBackupDir := filepath.Join(backupDir, "certificates")
	if err := os.MkdirAll(certsBackupDir, 0755); err != nil {
		return err
	}

	return filepath.Walk(s.config.CertificatesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(s.config.CertificatesPath, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(certsBackupDir, relPath)
		dstDir := filepath.Dir(dstPath)
		
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			return err
		}

		return s.copyFile(path, dstPath)
	})
}

func (s *BackupService) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

func (s *BackupService) cleanupOldBackups() error {
	backupsDir := "./backups"
	
	entries, err := os.ReadDir(backupsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var backupDirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.Contains(entry.Name(), "_") {
			backupDirs = append(backupDirs, entry.Name())
		}
	}

	if len(backupDirs) <= 10 {
		return nil
	}

	for i := 0; i < len(backupDirs)-10; i++ {
		oldBackupPath := filepath.Join(backupsDir, backupDirs[i])
		if err := os.RemoveAll(oldBackupPath); err != nil {
			s.logger.Warnf("Failed to remove old backup %s: %v", oldBackupPath, err)
		} else {
			s.logger.Infof("Removed old backup: %s", oldBackupPath)
		}
	}

	return nil
}
import { ALERTS_CONFIG } from '@/features/alerts'
import { INCIDENTS_CONFIG } from '@/features/incidents'
import { INVESTIGATIONS_CONFIG } from '@/features/investigations'
import { THREAT_INTEL_CONFIG } from '@/features/threat-intelligence'
import { THREAT_HUNTING_CONFIG } from '@/features/threat-hunting'
import { HealthCheck, useHealthCheck, useReadiness, checkHealth, checkReadiness, ApiClient } from '@/features/system'

describe('Feature Modules Foundation', () => {
  describe('Configuration Contracts', () => {
    it('ALERTS_CONFIG provides valid title and description', () => {
      expect(ALERTS_CONFIG.title).toBe('Alerts')
      expect(ALERTS_CONFIG.description).toBeDefined()
      expect(ALERTS_CONFIG.emptyMessage).toBe('No alerts have been triggered.')
    })

    it('INCIDENTS_CONFIG provides valid title and description', () => {
      expect(INCIDENTS_CONFIG.title).toBe('Incidents')
      expect(INCIDENTS_CONFIG.description).toBeDefined()
      expect(INCIDENTS_CONFIG.emptyMessage).toBe('No active incidents.')
    })

    it('INVESTIGATIONS_CONFIG provides valid title and description', () => {
      expect(INVESTIGATIONS_CONFIG.title).toBe('Investigations')
      expect(INVESTIGATIONS_CONFIG.description).toBeDefined()
      expect(INVESTIGATIONS_CONFIG.emptyMessage).toBe('No active investigations.')
    })

    it('THREAT_INTEL_CONFIG provides valid title and description', () => {
      expect(THREAT_INTEL_CONFIG.title).toBe('Threat Intelligence')
      expect(THREAT_INTEL_CONFIG.description).toBeDefined()
      expect(THREAT_INTEL_CONFIG.emptyMessage).toBe('No intelligence feeds configured.')
    })

    it('THREAT_HUNTING_CONFIG provides valid title and description', () => {
      expect(THREAT_HUNTING_CONFIG.title).toBe('Threat Hunting')
      expect(THREAT_HUNTING_CONFIG.description).toBeDefined()
      expect(THREAT_HUNTING_CONFIG.emptyMessage).toBe('No active hunting campaigns.')
    })
  })

  describe('System Feature Module Exports', () => {
    it('should export all health/readiness integration primitives', () => {
      expect(HealthCheck).toBeDefined()
      expect(useHealthCheck).toBeDefined()
      expect(useReadiness).toBeDefined()
      expect(checkHealth).toBeDefined()
      expect(checkReadiness).toBeDefined()
      expect(ApiClient).toBeDefined()
    })
  })
})

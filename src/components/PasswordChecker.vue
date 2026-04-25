<template>
  <div class="card">
    <div class="card-header">
      <div class="shield-icon">🔐</div>
      <h1>Password Analyzer</h1>
      <p class="subtitle">Check strength & data breach exposure</p>
    </div>

    
    <div class="input-section">
      <label for="password-input">Enter Password</label>
      <div class="input-wrapper">
        <input
          id="password-input"
          :type="showPassword ? 'text' : 'password'"
          v-model="password"
          placeholder="Type your password..."
          autocomplete="off"
          spellcheck="false"
        />
        <button
          class="toggle-btn"
          @click="showPassword = !showPassword"
          :title="showPassword ? 'Hide password' : 'Show password'"
          type="button"
        >
          {{ showPassword ? '🙈' : '👁️' }}
        </button>
      </div>
    </div>

    
    <div class="strength-section" v-if="password.length > 0">
      <div class="strength-header">
        <span class="strength-label">Strength</span>
        <span class="strength-text" :class="strengthInfo.class">{{ strengthInfo.label }}</span>
      </div>
      <div class="strength-bar-track">
        <div
          class="strength-bar-fill"
          :class="strengthInfo.class"
          :style="{ width: strengthInfo.width }"
        ></div>
      </div>
      <
      <ul class="criteria-list">
        <li :class="{ met: criteria.length8 }">
          <span class="check">{{ criteria.length8 ? '✓' : '○' }}</span> At least 8 characters
        </li>
        <li :class="{ met: criteria.length12 }">
          <span class="check">{{ criteria.length12 ? '✓' : '○' }}</span> 12+ characters (recommended)
        </li>
        <li :class="{ met: criteria.uppercase }">
          <span class="check">{{ criteria.uppercase ? '✓' : '○' }}</span> Uppercase letter
        </li>
        <li :class="{ met: criteria.lowercase }">
          <span class="check">{{ criteria.lowercase ? '✓' : '○' }}</span> Lowercase letter
        </li>
        <li :class="{ met: criteria.number }">
          <span class="check">{{ criteria.number ? '✓' : '○' }}</span> Number
        </li>
        <li :class="{ met: criteria.special }">
          <span class="check">{{ criteria.special ? '✓' : '○' }}</span> Special character (!@#$…)
        </li>
      </ul>
    </div>

    
    <div class="privacy-notice">
      <span class="lock-icon">🔒</span>
      <p>
        <strong>Your privacy is protected.</strong> Only the first 5 characters of a SHA-1 hash
        are sent to the breach API — your actual password <em>never</em> leaves your device.
      </p>
    </div>

    
    <div class="breach-section">
      <button
        class="breach-btn"
        @click="checkBreach"
        :disabled="password.length === 0 || isChecking"
        type="button"
      >
        <span v-if="isChecking" class="spinner"></span>
        <span v-else>🔍</span>
        {{ isChecking ? 'Checking...' : 'Check if Breached' }}
      </button>

      
      <div v-if="breachResult !== null" class="breach-result" :class="breachResult.found ? 'result-danger' : 'result-safe'">
        <div class="result-icon">{{ breachResult.found ? '⚠️' : '✅' }}</div>
        <div class="result-content">
          <p v-if="breachResult.found" class="result-title danger-text">
            Found in {{ breachResult.count.toLocaleString() }} data breach{{ breachResult.count === 1 ? '' : 'es' }}
          </p>
          <p v-else class="result-title safe-text">
            Not found in any known breach
          </p>
          <p v-if="breachResult.found" class="result-detail">
            This password has been exposed. Avoid using it — attackers may already have it.
          </p>
          <p v-else class="result-detail">
            This password wasn't found in any known data leaks. That's a good sign, but strength still matters.
          </p>
        </div>
      </div>

      
      <div v-if="breachError" class="breach-result result-error">
        <div class="result-icon">⚡</div>
        <div class="result-content">
          <p class="result-title">Could not reach the breach database</p>
          <p class="result-detail">{{ breachError }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const password = ref('')
const showPassword = ref(false)
const isChecking = ref(false)
const breachResult = ref(null)
const breachError = ref(null)

// Clear breach result when the password changes
watch(password, () => {
  breachResult.value = null
  breachError.value = null
})

// Individual criteria flags
const criteria = computed(() => ({
  length8: password.value.length >= 8,
  length12: password.value.length >= 12,
  uppercase: /[A-Z]/.test(password.value),
  lowercase: /[a-z]/.test(password.value),
  number: /[0-9]/.test(password.value),
  special: /[^A-Za-z0-9]/.test(password.value),
}))

// Score 0–4
const score = computed(() => {
  const c = criteria.value
  let s = 0
  if (c.length8) s++
  if (c.length12) s++
  if (c.uppercase) s++
  if (c.lowercase) s++
  if (c.number) s++
  if (c.special) s++
  // Map 0–6 → 0–4
  if (s === 0) return 0
  if (s <= 2) return 1
  if (s <= 3) return 2
  if (s <= 5) return 3
  return 4
})

const strengthInfo = computed(() => {
  const levels = [
    { label: 'Too Weak', class: 'strength-weak',      width: '10%' },
    { label: 'Weak',     class: 'strength-weak',      width: '25%' },
    { label: 'Fair',     class: 'strength-fair',      width: '50%' },
    { label: 'Strong',   class: 'strength-strong',    width: '75%' },
    { label: 'Very Strong', class: 'strength-best',   width: '100%' },
  ]
  return levels[score.value]
})

// SHA-1 hash via Web Crypto API
async function sha1Hex(str) {
  const encoded = new TextEncoder().encode(str)
  const hashBuffer = await crypto.subtle.digest('SHA-1', encoded)
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

async function checkBreach() {
  if (!password.value) return
  isChecking.value = true
  breachResult.value = null
  breachError.value = null

  try {
    const hash = await sha1Hex(password.value)
    const prefix = hash.slice(0, 5)
    const suffix = hash.slice(5)

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
    })

    if (!response.ok) {
      throw new Error(`API responded with status ${response.status}`)
    }

    const text = await response.text()
    const lines = text.split('\n')

    let count = 0
    for (const line of lines) {
      const [hashSuffix, countStr] = line.trim().split(':')
      if (hashSuffix === suffix) {
        count = parseInt(countStr, 10)
        break
      }
    }

    breachResult.value = { found: count > 0, count }
  } catch (err) {
    breachError.value = err.message || 'Unknown error. Check your network connection.'
  } finally {
    isChecking.value = false
  }
}
</script>

<style scoped>
.card {
  background: #1a1d27;
  border: 1px solid #2a2d3e;
  border-radius: 16px;
  padding: 2.5rem;
  width: 100%;
  max-width: 520px;
  box-shadow: 0 8px 40px rgba(0, 0, 0, 0.5);
}

/* Header */
.card-header {
  text-align: center;
  margin-bottom: 2rem;
}

.shield-icon {
  font-size: 2.5rem;
  margin-bottom: 0.75rem;
}

h1 {
  color: #e8eaf6;
  font-size: 1.6rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.subtitle {
  color: #6b7280;
  font-size: 0.875rem;
  margin-top: 0.25rem;
}

/* Input */
.input-section {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  color: #9ca3af;
  font-size: 0.8125rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.5rem;
}

.input-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}

input {
  width: 100%;
  background: #0f1117;
  border: 1px solid #2a2d3e;
  border-radius: 10px;
  color: #e8eaf6;
  font-size: 1rem;
  padding: 0.75rem 3rem 0.75rem 1rem;
  outline: none;
  transition: border-color 0.2s;
  font-family: 'Courier New', monospace;
  letter-spacing: 0.05em;
}

input:focus {
  border-color: #4f46e5;
  box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15);
}

input::placeholder {
  color: #3d4151;
  font-family: 'Segoe UI', system-ui, sans-serif;
  letter-spacing: normal;
}

.toggle-btn {
  position: absolute;
  right: 0.75rem;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1.1rem;
  padding: 0.25rem;
  opacity: 0.7;
  transition: opacity 0.2s;
  line-height: 1;
}

.toggle-btn:hover {
  opacity: 1;
}

/* Strength Section */
.strength-section {
  margin-bottom: 1.5rem;
}

.strength-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.strength-label {
  color: #9ca3af;
  font-size: 0.8125rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.strength-text {
  font-size: 0.875rem;
  font-weight: 600;
}

.strength-bar-track {
  background: #0f1117;
  border-radius: 99px;
  height: 8px;
  overflow: hidden;
  border: 1px solid #2a2d3e;
}

.strength-bar-fill {
  height: 100%;
  border-radius: 99px;
  transition: width 0.4s ease, background-color 0.4s ease;
}

/* Strength levels */
.strength-weak  { color: #ef4444; background-color: #ef4444; }
.strength-fair  { color: #f97316; background-color: #f97316; }
.strength-strong { color: #eab308; background-color: #eab308; }
.strength-best  { color: #22c55e; background-color: #22c55e; }

/* Criteria list */
.criteria-list {
  list-style: none;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.375rem;
  margin-top: 1rem;
}

.criteria-list li {
  color: #4b5563;
  font-size: 0.8rem;
  display: flex;
  align-items: center;
  gap: 0.375rem;
  transition: color 0.2s;
}

.criteria-list li.met {
  color: #9ca3af;
}

.criteria-list li .check {
  font-size: 0.75rem;
  color: #4b5563;
  transition: color 0.2s;
}

.criteria-list li.met .check {
  color: #22c55e;
}

/* Privacy Notice */
.privacy-notice {
  display: flex;
  gap: 0.75rem;
  align-items: flex-start;
  background: #0f1117;
  border: 1px solid #2a2d3e;
  border-radius: 10px;
  padding: 0.875rem 1rem;
  margin-bottom: 1.5rem;
}

.lock-icon {
  font-size: 1rem;
  flex-shrink: 0;
  margin-top: 1px;
}

.privacy-notice p {
  color: #6b7280;
  font-size: 0.8rem;
  line-height: 1.5;
}

.privacy-notice strong {
  color: #9ca3af;
}

/* Breach section */
.breach-section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.breach-btn {
  width: 100%;
  background: #4f46e5;
  color: #fff;
  border: none;
  border-radius: 10px;
  padding: 0.875rem 1.5rem;
  font-size: 0.9375rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  transition: background-color 0.2s, transform 0.1s, opacity 0.2s;
}

.breach-btn:hover:not(:disabled) {
  background: #4338ca;
}

.breach-btn:active:not(:disabled) {
  transform: scale(0.99);
}

.breach-btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

/* Spinner */
.spinner {
  display: inline-block;
  width: 1rem;
  height: 1rem;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  flex-shrink: 0;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Results */
.breach-result {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  border-radius: 10px;
  padding: 1rem 1.125rem;
  border: 1px solid;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(4px); }
  to   { opacity: 1; transform: translateY(0); }
}

.result-danger {
  background: rgba(239, 68, 68, 0.08);
  border-color: rgba(239, 68, 68, 0.3);
}

.result-safe {
  background: rgba(34, 197, 94, 0.08);
  border-color: rgba(34, 197, 94, 0.3);
}

.result-error {
  background: rgba(234, 179, 8, 0.08);
  border-color: rgba(234, 179, 8, 0.3);
}

.result-icon {
  font-size: 1.25rem;
  flex-shrink: 0;
  margin-top: 1px;
}

.result-content {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.result-title {
  font-size: 0.9375rem;
  font-weight: 600;
}

.danger-text { color: #f87171; }
.safe-text   { color: #4ade80; }

.result-detail {
  color: #6b7280;
  font-size: 0.8125rem;
  line-height: 1.5;
}
</style>

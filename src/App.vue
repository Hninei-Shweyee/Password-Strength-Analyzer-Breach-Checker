<template>
  <div id="app">
    <PasswordChecker />
  </div>
</template>

<script setup>
import PasswordChecker from './components/PasswordChecker.vue'
</script>

<style>
*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background-color: #0f1117;
  min-height: 100vh;
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
}

#app {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem 1rem;
}
</style>

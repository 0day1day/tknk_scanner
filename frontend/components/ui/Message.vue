<template>
  <div id="message-container">
    <div id="message-content">
      <slot></slot>
    </div>
  </div>
</template>

<script>
  export default {
    name: "Message"
  }
</script>

<style lang="stylus" scoped>
  #message-container
    display flex
    justify-content center
    align-items center
  #message-content
    width 100%
    height 100%

</style>

<template>
  <div id="page-container">
    <b-container id="page-content">
      <slot></slot>
    </b-container>
  </div>
</template>

<script>
  export default {
    name: "Page"
  }
</script>

<style lang="stylus" scoped>
  #page-container
    display flex
    justify-content center
    width 100vw
    min-width 100vw
    #page-content
      height calc(100% - 60px)
      min-width 80vw
      width 80vw


</style>

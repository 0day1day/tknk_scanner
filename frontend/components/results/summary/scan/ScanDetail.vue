<template>
  <b-table :items="scanSummary" class="summary-table" stacked fixed small></b-table>
</template>

<script>
  export default {
    name: "ScanSummary",
    props: [
      'scanSummary'
    ]
  }
</script>

<style lang="stylus" scoped>

</style>

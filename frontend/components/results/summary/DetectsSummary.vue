<template>
  <b-table :items="detectsSummary" class="summary-table" stacked fixed small></b-table>
</template>

<script>
  export default {
    name: "DetectsSummary",
    props: [
      'detectsSummary'
    ]
  }
</script>

<style scoped>

</style>

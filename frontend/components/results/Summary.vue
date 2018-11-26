<template>
  <div class="summary">
    <b-table :items="summary" class="summary-table" stacked>

    </b-table>
  </div>
</template>

<script>
  export default {
    name: "ResultsSummary",
    props: [
      "summary"
    ]
  }
</script>

<style scoped>

</style>

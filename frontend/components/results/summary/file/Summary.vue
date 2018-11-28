<template>
  <b-row>
    <b-col sm="6">
      <file-summary :file-summary="file_summary" />
    </b-col>
    <b-col sm="6">
      <detects-summary :detects-summary="detects_summary" />
    </b-col>
  </b-row>
</template>

<script>
  import { mapGetters } from 'vuex'
  import FileSummary from '~/components/results/summary/file/FileSummary'
  import DetectsSummary from '~/components/results/summary/file/DetectsSummary'

  export default {
    name: "Summary",
    components: {
      FileSummary,
      DetectsSummary
    },
    computed: {
      ... mapGetters({
        'file_summary': 'report/file_summary',
        'detects_summary': 'report/detects_summary'
      })
    }
  }
</script>

<style lang="stylus" scoped>
</style>

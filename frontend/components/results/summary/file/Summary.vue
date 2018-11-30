<template>
  <b-row>
    <b-col sm="2">
      <div class="text-center file">
        <i class="fas fa-file fa-10x"></i>
        <h3 class="file_name">
          {{ file_name }}
        </h3>
        <b-badge :variant="is_in_vt ? 'primary' : 'warning'" :href="is_in_vt ? 'https://www.virustotal.com/#/file/' + sha256 : null" target="_blank">
          VirusTotal
          <b-badge variant="light" class="num">
            {{ is_in_vt ? "Found" : "Not Found" }}
          </b-badge>
        </b-badge>
      </div>
    </b-col>
    <b-col sm="5">
      <file-summary :file-summary="file_summary" />
    </b-col>
    <b-col sm="5">
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
        'detects_summary': 'report/detects_summary',
        'file_name': 'report/file_name',
        'is_in_vt': 'report/is_in_vt',
        'sha256': 'report/sha256'
      })
    }
  }
</script>

<style lang="stylus" scoped>
  .file
    margin 1em
  .file_name
    font-size 1.12em
    margin-top 0.5em
    word-break break-all
  .num
    margin-left 0.25em
</style>

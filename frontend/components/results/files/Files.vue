<template>
  <b-table :items="report.scans" v-if="report.scans.length !== 0" :fields="headers" class="dropped-file-table">
    <template slot="detect_rule" slot-scope="data" class="detect-rules">
      <div class="badges">
        <b-badge variant="danger" v-for="(l, k) in data.value" :key="k" class="detect-label" v-if="data.value.length !== 0">{{ l }}</b-badge>
      </div>
    </template>
  </b-table>
  <div class="no-dropped" v-else>
    <p>No file dropped.</p>
  </div>
</template>

<script>
  import { mapState } from 'vuex'

  export default {
    name: "Files",
    computed: {
      headers() {
        return [
          {
            key: 'file_name',
            label: 'File Name'
          },
          {
            key: 'detect_rules',
            label: 'Detect Rule'
          },
        ]
      },
      ... mapState([ 'report' ])
    }
  }
</script>

<style lang="stylus">
  .dropped-file-table
    td
      border-top 1px solid gray
</style>

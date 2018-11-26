<template>
<page>
  <Message class="progress-message" v-if="is_processing">
    <i class="fas fa-spinner fa-spin fa-10x"></i>
    <p>Now analyzing ...</p>
  </Message>
  <div v-if="!is_processing">
    <b-container fluid>
      <b-row>
        <b-col>
          <h1>Result</h1>
        </b-col>
      </b-row>
      <b-row>
        <b-col sm="4" class="status">
          <div class="status-success" v-if="report.result.is_success">
            <i class="fas fa-check-circle fa-10x"></i>
            <h2>Success!</h2>
          </div>
          <div class="status-fail" v-else>
            <i class="fas fa-times-circle fa-10x"></i>
            <h2>Failed</h2>
          </div>
        </b-col>
        <b-col sm="4">
          <b-table :items="scan_summary" class="summary-table" stacked></b-table>
        </b-col>
        <b-col sm="4">
          <b-table :items="file_summary" class="summary-table" stacked></b-table>
        </b-col>
      </b-row>
      <b-row>
        <b-col>
          <b-table :items="report.scans" class="summary-table">
            <template slot="detect_rule" slot-scope="data">
              <b-badge variant="danger" v-for="(l, k) in data.value" :key="k" class="detect-label">{{ l }}</b-badge>
            </template>
          </b-table>
        </b-col>
      </b-row>
    </b-container>
  </div>
</page>
</template>

<script>
  import Page from '~/components/ui/Page'
  import Message from '~/components/ui/Message'
  import { mapState, mapGetters } from 'vuex'

  export default {
    name: "result-index",
    components: {
      Page,
      Message
    },
    data() {
      return {
        interval: null
      }
    },
    computed: {
      is_processing () {
        return this.report.status_code === 1 || this.report.status_code === null;
      },
      ... mapState([ 'report' ]),
      ... mapGetters({
        'file_summary': 'report/file_summary',
        'scan_summary': 'report/scan_summary'
      })
    },
    validate({ params }){
      return /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.test(params.resultid);
    },
    created () {
      this.fetch_data();
      this.interval = setInterval(this.fetch_data, 5000);
    },
    methods: {
      async fetch_data() {
        if (this.report.status_code === null || this.report.status_code === 1) {
          let res = await this.$axios.$get('/results/' + this.$route.params.resultid, { progress: false }).catch(e => {
            clearInterval(this.interval);
            throw this.$root.error(e);
          });
          if(res.status_code !== 1) {
            this.$store.commit('report/set_result', res);
          }
        } else {
          clearInterval(this.interval);
        }
      }
    },
    beforeDestroy() {
      clearInterval(this.interval);
      this.$store.commit('report/destoroy')
    },
  }
</script>

<style lang="stylus" scoped>
  .analyze-result
    width 100%
    margin 0
  .progress-message
    text-align center
    i
      color #00ff00
  .result-container
    height calc(100% - 60px)
    display flex
    justify-content center
    align-items center
  .status
    text-align center
    .status-success
      color #00ff00
    .status-fail
      color #ff3300
    .detect-label
      margin 0 0.5em
</style>
<style lang="stylus">
  .table
    td
      border-top none
</style>

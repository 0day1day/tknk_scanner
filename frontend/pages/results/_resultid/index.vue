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
      <scan-summary />
      <file-summary />
      <b-row>
        <b-col>
          <h2>Dropped Files</h2>
        </b-col>
      </b-row>
      <b-row>
        <b-col>
          <files />
        </b-col>
      </b-row>
    </b-container>
  </div>
</page>
</template>

<script>
  import Page from '~/components/ui/Page'
  import Message from '~/components/ui/Message'
  import ScanSummary from '~/components/results/summary/scan/Summary'
  import FileSummary from '~/components/results/summary/file/Summary'
  import Files from '~/components/results/files/Files'
  import { mapState } from 'vuex'

  export default {
    name: "result-index",
    components: {
      ScanSummary,
      FileSummary,
      Page,
      Message,
      Files,
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
      ...mapState([ 'report' ])
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
      this.$store.commit('report/destoroy');
    },
  }
</script>

<style lang="stylus" scoped>
  .progress-message
    text-align center
    i
      color #00ff00
</style>

<style lang="stylus">
  .table
    td
      border-top none
</style>

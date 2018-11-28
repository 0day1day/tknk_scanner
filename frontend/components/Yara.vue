<template>
  <div>
    <b-badge variant="danger" @click="show_detail">{{ yara }}</b-badge>
    <b-modal ref="ruleDetail" class="detail" hide-footer :title="yara">
      <pre class="d-block">{{ rule }}</pre>
      <b-btn class="mt-3" variant="outline-danger" block @click="hide_detail">Close</b-btn>
    </b-modal>
  </div>
</template>

<script>
  export default {
    name: "Yara",
    props: [
      'yara'
    ],
    data() {
      return {
        rule: null
      }
    },
    methods: {
      show_detail() {
        this.fetch_rule();
        this.$refs.ruleDetail.show();
      },
      hide_detail() {
        this.$refs.ruleDetail.hide();
      },
      fetch_rule() {
        this.$axios.get(`/yara/${this.yara}`, { progress: false }).then(res => {
          this.rule = res.data.rule;
        }).catch(e => {
          console.log(`Fetching rule error: ${e}`);
          this.rule = "Rule Not Found";
        });
      }
    }
  }
</script>

<style lang="stylus" scoped>
  span
    margin 0 0.5em 0 0
  .detail
    color black
</style>

<template>
  <b-table :items="detectsSummary" class="summary-table" stacked fixed small>
    <template slot="DIE Indicators" slot-scope="die">
      <b-badge variant="info" v-for="(v, k) in die.value" :key="k" class="die">{{ v }}</b-badge>
    </template>
    <template slot="detect_rules" slot-scope="rules">
      <div class="badges">
        <yara v-for="(l, k) in rules['value']" :key="k" :yara="l" />
      </div>
    </template>
  </b-table>
</template>

<script>
  import Yara from '~/components/Yara'
  export default {
    name: "DetectsSummary",
    props: [
      'detectsSummary'
    ],
    components: {
      Yara
    }
  }
</script>

<style lang="stylus" scoped>
  .die
    word-break break-all
    margin 0 0.5em 0 0
  .badges
    word-break break-word
</style>

<template>
  <b-table :items="fileSummary" class="summary-table" stacked fixed small>
    <template slot="MD5" slot-scope="md5">
      <hash :hash="md5.value" />
    </template>
    <template slot="SHA1" slot-scope="sha1">
      <hash :hash="sha1.value" />
    </template>
    <template slot="SHA256" slot-scope="sha256">
      <hash :hash="sha256.value" />
    </template>
  </b-table>
</template>

<script>
  import Hash from '~/components/results/summary/Hash'

  export default {
    name: "FileSummary",
    props: [
      'fileSummary'
    ],
    components: {
      Hash
    }
  }
</script>

<style lang="stylus" scoped>
</style>

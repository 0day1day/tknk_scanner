<template>
  <b-dropdown-item :to="result_link"><i :class="status_icon"></i>{{job.job_id}}</b-dropdown-item>
</template>

<script>
  export default {
    name: "Job",
    props: [
      "job"
    ],
    data() {
      return {
        status: null,
        is_success: false
      }
    },
    mounted() {
      this.fetch_result();
      setTimeout(this.fetch_result, 9000);
    },
    watch: {
      status(oldStatus, newStatus){
        if (newStatus > 0) {
          setTimeout(this.fetch_result, 9000);
        }
      }
    },
    methods: {
      fetch_result() {
        this.$axios.get(`/results/${this.job.job_id}`).then(res => {
          this.status = res.data["status_code"];
          if (res.data["status_code"] === 0){
            this.is_success = res.data["result"]["result"]["is_success"];
          }
        }).catch(e => {
          console.error(`Fetching result error: ${e}`);
        });
      },
      status_icon() {
        let templates = ["fas"];
        if (this.status === 1) {
          // processing
          templates = templates.concat(["fa-spinner", "fa-spin"]);
        } else if (this.status === 0 && this.is_success) {
          // done and scanning success
          templates = templates.concat(["fa-check-circle"]);
        } else if (this.status === 0 && !this.is_success) {
          // done, but fail scanning
          templates = templates.concat(["fa-times-circle"]);
        } else {
          // not implemented state
          templates = templates.concat(["fa-question-circle"]);
        }
        return templates;
      },
      result_link() {
        return {
          name: "results-resultId",
          params: {
            resultId: this.job.job_id
          }
        }
      }
    }
  }
</script>

<style scoped>

</style>

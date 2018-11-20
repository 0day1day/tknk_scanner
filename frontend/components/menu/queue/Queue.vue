<template>
  <div>
    <b-nav-item-dropdown :text="label" v-if="jobs.length !== 0">
      <job :resultId="job" v-for="(job, index) in jobs" :key="index" />
    </b-nav-item-dropdown>
    <b-navbar-nav v-else>
      <b-nav-text>{{ label }}</b-nav-text>
    </b-navbar-nav>
  </div>
</template>
<script>
  import Job from '~/components/menu/queue/Job.vue'

  export default {
    name: "Queue",
    components: {
      Job
    },
    data() {
      return {
        jobs: [],
      }
    },
    mounted() {
      this.fetch_jobs();
    },
    watch: {
      jobs(oldJobs, newJobs) {
        if (newJobs.length > 0){
          setTimeout(this.fetch_jobs, 5000);
        } else {
          setTimeout(this.fetch_jobs, 10000);
        }
      }
    },
    computed: {
      label() {
        return `Standby: ${this.jobs.length}`;
      }
    },
    methods: {
      fetch_jobs() {
        this.$axios.get("/jobs").then(res => {
          this.jobs = res.data['job_ids'];
        }).catch(e => {
          console.error(`Fetching jobs caused a error: ${e}`);
        });
      }
    }
  }
</script>

<style scoped>

</style>

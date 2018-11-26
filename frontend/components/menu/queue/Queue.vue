<template>
  <div>
    <b-navbar-nav>
      <b-nav-item :to="{ name: 'jobs' }">{{ label }}</b-nav-item>
    </b-navbar-nav>
  </div>
</template>
<script>
  import { mapState, mapMutations } from 'vuex'

  export default {
    name: "Queue",
    mounted() {
      this.next_tick();
    },
    computed: {
      label() {
        let current_length = this.jobs.current !== null ? 1 : 0;
        return `Processing: ${current_length} / Queued: ${this.jobs.queued.length}`;
      },
      ... mapState([ 'jobs' ])
    },
    methods: {
      next_tick() {
        this.fetch_jobs();
        if(this.jobs.current !== null){
          setTimeout(this.next_tick, 5000);
        } else {
          setTimeout(this.next_tick, 10000);
        }
      },
      fetch_jobs() {
        this.$axios.get("/jobs", { progress: false }).then(res => {
          if (res.data.status_code === 0){
            this.change_current(res.data.current_job);
            this.push_queued_jobs(res.data.queued_jobs);
          }
        }).catch(e => {
          console.error(`Fetching jobs caused a error: ${e}`);
        });
      },
      ... mapMutations({
        'change_current': 'jobs/change_current',
        'push_queued_jobs': 'jobs/push_queued_jobs'
      })
    }
  }
</script>

<style scoped>

</style>

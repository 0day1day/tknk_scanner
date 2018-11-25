export const state = () => ({
  uuid: null,
  mode: null,
  result: null,
  run_time: null,
  scans: null,
  timestamp: null,
  status_code: null,
  target_scan: null
});

export const getters = {
  scanned_files(state) {
    return [state.target_scan].concat(state.scans);
  },
  summary(state) {
    return [
      {
        Mode: state.mode,
        Detail: state.result.detail,
        "Running Time": state.run_time,
        Timestamp: state.timestamp
      }
    ]
  },
};

export const mutations = {
  set_result(state, d) {
    state.uuid = d.report.uuid;
    state.mode = d.report.mode;
    state.result = d.report.result;
    state.run_time = d.report.run_time;
    state.scans = d.report.scans;
    state.timestamp = d.report.timestamp;
    state.status_code = d.status_code;
    state.target_scan = d.report.target_scan;
  },
  destoroy(state) {
    state.uuid = null;
    state.mode = null;
    state.result = null;
    state.run_time = null;
    state.scans = null;
    state.timestamp = null;
    state.status_code = null;
    state.target_scan = null;
  }
};

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
  scan_summary(state) {
    return [
      {
        Mode: state.mode,
        Detail: state.result.detail,
        "Running Time": state.run_time,
        Timestamp: state.timestamp,
      }
    ]
  },
  file_summary(state){
    return [
      {
        "File Name": state.target_scan.file_name,
        Hashes: [state.target_scan.md5, state.target_scan.sha1, state.target_scan.sha256],
        "Detect Rules": state.target_scan.detect_rule
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

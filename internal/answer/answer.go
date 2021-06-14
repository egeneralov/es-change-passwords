package answer

import "time"

type Root struct {
	Name        string `json:"name"`
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number                           string    `json:"number"`
		BuildFlavor                      string    `json:"build_flavor"`
		BuildType                        string    `json:"build_type"`
		BuildHash                        string    `json:"build_hash"`
		BuildDate                        time.Time `json:"build_date"`
		BuildSnapshot                    bool      `json:"build_snapshot"`
		LuceneVersion                    string    `json:"lucene_version"`
		MinimumWireCompatibilityVersion  string    `json:"minimum_wire_compatibility_version"`
		MinimumIndexCompatibilityVersion string    `json:"minimum_index_compatibility_version"`
	} `json:"version"`
	Tagline string `json:"tagline"`
}

/*
type Exception struct {
	Error struct {
		RootCause []struct {
			Type   string `json:"types"`
			Reason string `json:"reason"`
			Header struct {
				WwwAuthenticate []string `json:"WWW-Authenticate"`
			} `json:"header"`
		} `json:"root_cause"`
		Type   string `json:"types"`
		Reason string `json:"reason"`
		Header struct {
			WwwAuthenticate []string `json:"WWW-Authenticate"`
		} `json:"header"`
	} `json:"error"`
	Status int `json:"status"`
}
*/

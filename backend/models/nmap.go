package models

type NmapRun struct {
	Hosts []Host `xml:"host" json:"hosts"`
}

type Host struct {
	Addresses []Address `xml:"address" json:"addresses"`
	Ports     Ports     `xml:"ports" json:"ports"`
}

type Address struct {
	Addr string `xml:"addr,attr" json:"addr"`
}

type Ports struct {
	Ports []Port `xml:"port" json:"ports"`
}

type Port struct {
	PortID  string  `xml:"portid,attr" json:"port"`
	Proto   string  `xml:"protocol,attr" json:"protocol"`
	State   State   `xml:"state"`
	Service Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr" json:"state"`
}

type Service struct {
	Name string `xml:"name,attr" json:"name"`
}

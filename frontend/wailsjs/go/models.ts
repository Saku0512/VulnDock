export namespace main {
	
	export class PocFile {
	    name: string;
	    type: string;
	    size: number;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new PocFile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.size = source["size"];
	        this.data = source["data"];
	    }
	}
	export class Report {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    cvssVersion: string;
	    cvssScore: string;
	    cvssVector: string;
	    status: string;
	    submittedAt: string;
	    reportUrl: string;
	    tags: string[];
	    pocFiles: PocFile[];
	    createdAt: string;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.program = source["program"];
	        this.asset = source["asset"];
	        this.cvssVersion = source["cvssVersion"];
	        this.cvssScore = source["cvssScore"];
	        this.cvssVector = source["cvssVector"];
	        this.status = source["status"];
	        this.submittedAt = source["submittedAt"];
	        this.reportUrl = source["reportUrl"];
	        this.tags = source["tags"];
	        this.pocFiles = this.convertValues(source["pocFiles"], PocFile);
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ReportDraft {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    cvssVersion: string;
	    cvssScore: string;
	    cvssVector: string;
	    status: string;
	    submittedAt: string;
	    reportUrl: string;
	    tags: string[];
	    pocFiles: PocFile[];
	
	    static createFrom(source: any = {}) {
	        return new ReportDraft(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.program = source["program"];
	        this.asset = source["asset"];
	        this.cvssVersion = source["cvssVersion"];
	        this.cvssScore = source["cvssScore"];
	        this.cvssVector = source["cvssVector"];
	        this.status = source["status"];
	        this.submittedAt = source["submittedAt"];
	        this.reportUrl = source["reportUrl"];
	        this.tags = source["tags"];
	        this.pocFiles = this.convertValues(source["pocFiles"], PocFile);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}


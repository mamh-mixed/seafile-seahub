(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[13],{1577:function(e,t,a){a(54),e.exports=a(1701)},1578:function(e,t,a){},1701:function(e,t,a){"use strict";a.r(t);var i=a(6),n=a(7),s=a(9),c=a(8),r=a(2),o=a.n(r),l=a(24),b=a.n(l),d=a(17),h=a(13),m=a.n(h),j=a(5),u=a(1),g=a(10),p=a(16),O=a(37),f=a(20),x=a(51),D=a(323),v=a(4),P=a(247),w=a.n(P),L=a(11),C=a(0),y=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).handleInputChange=function(e){n.setState({inputValue:e})},n.formSubmit=function(){var e=n.state.inputValue.map((function(e,t){return e.value})).join(","),t=n.props,a=t.repoID,i=t.commitID;n.setState({submitBtnDisabled:!0}),g.a.updateRepoCommitLabels(a,i,e).then((function(e){n.props.updateCommitLabels(e.data.revisionTags.map((function(e,t){return e.tag}))),n.props.toggleDialog(),L.a.success(Object(u.nb)("Successfully edited labels."))})).catch((function(e){var t=j.a.getErrorMsg(e);n.setState({formErrorMsg:t,submitBtnDisabled:!1})}))},n.state={inputValue:n.props.commitLabels.map((function(e,t){return{label:e,value:e}})),submitBtnDisabled:!1},n}return Object(n.a)(a,[{key:"render",value:function(){var e=this.state.formErrorMsg;return Object(C.jsxs)(v.x,{isOpen:!0,centered:!0,toggle:this.props.toggleDialog,children:[Object(C.jsx)(v.A,{toggle:this.props.toggleDialog,children:Object(u.nb)("Edit labels")}),Object(C.jsx)(v.y,{children:Object(C.jsxs)(o.a.Fragment,{children:[Object(C.jsx)(w.a,{defaultValue:this.props.commitLabels.map((function(e,t){return{label:e,value:e}})),isMulti:!0,onChange:this.handleInputChange,placeholder:""}),e&&Object(C.jsx)("p",{className:"error m-0 mt-2",children:e})]})}),Object(C.jsx)(v.z,{children:Object(C.jsx)("button",{className:"btn btn-primary",disabled:this.state.submitBtnDisabled,onClick:this.formSubmit,children:Object(u.nb)("Submit")})})]})}}]),a}(o.a.Component),M=(a(128),a(144),a(1578),window.app.pageOptions),N=M.repoID,k=M.repoName,S=M.userPerm,I=M.showLabel,_=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).getItems=function(e){g.a.getRepoHistory(N,e,n.state.perPage).then((function(t){n.setState({isLoading:!1,currentPage:e,items:t.data.data,hasNextPage:t.data.more})})).catch((function(e){n.setState({isLoading:!1,errorMsg:j.a.getErrorMsg(e,!0)})}))},n.resetPerPage=function(e){n.setState({perPage:e},(function(){n.getItems(1)}))},n.onSearchedClick=function(e){if(!0===e.is_dir){var t=u.kc+"library/"+e.repo_id+"/"+e.repo_name+e.path;Object(d.c)(t,{repalce:!0})}else{var a=u.kc+"lib/"+e.repo_id+"/file"+j.a.encodePath(e.path);window.open("about:blank").location.href=a}},n.goBack=function(e){e.preventDefault(),window.history.back()},n.state={isLoading:!0,errorMsg:"",currentPage:1,perPage:25,hasNextPage:!1,items:[]},n}return Object(n.a)(a,[{key:"componentDidMount",value:function(){var e=this,t=new URL(window.location).searchParams,a=this.state,i=a.currentPage,n=a.perPage;this.setState({perPage:parseInt(t.get("per_page")||n),currentPage:parseInt(t.get("page")||i)},(function(){e.getItems(e.state.currentPage)}))}},{key:"render",value:function(){return Object(C.jsx)(o.a.Fragment,{children:Object(C.jsxs)("div",{className:"h-100 d-flex flex-column",children:[Object(C.jsxs)("div",{className:"top-header d-flex justify-content-between",children:[Object(C.jsx)("a",{href:u.kc,children:Object(C.jsx)("img",{src:u.Lb+u.Gb,height:u.Fb,width:u.Hb,title:u.lc,alt:"logo"})}),Object(C.jsx)(x.a,{onSearchedClick:this.onSearchedClick})]}),Object(C.jsx)("div",{className:"flex-auto container-fluid pt-4 pb-6 o-auto",children:Object(C.jsx)("div",{className:"row",children:Object(C.jsxs)("div",{className:"col-md-10 offset-md-1",children:[Object(C.jsx)("h2",{dangerouslySetInnerHTML:{__html:j.a.generateDialogTitle(Object(u.nb)("{placeholder} Modification History"),k)}}),Object(C.jsx)("a",{href:"#",className:"go-back",title:Object(u.nb)("Back"),onClick:this.goBack,children:Object(C.jsx)("span",{className:"fas fa-chevron-left"})}),"rw"==S&&Object(C.jsx)("p",{className:"tip",children:Object(u.nb)("Tip: a snapshot will be generated after modification, which records the library state after the modification.")}),Object(C.jsx)(B,{isLoading:this.state.isLoading,errorMsg:this.state.errorMsg,items:this.state.items,currentPage:this.state.currentPage,hasNextPage:this.state.hasNextPage,curPerPage:this.state.perPage,resetPerPage:this.resetPerPage,getListByPage:this.getItems})]})})})]})})}}]),a}(o.a.Component),B=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).getPreviousPage=function(){n.props.getListByPage(n.props.currentPage-1)},n.getNextPage=function(){n.props.getListByPage(n.props.currentPage+1)},n.theadData=I?[{width:"43%",text:Object(u.nb)("Description")},{width:"12%",text:Object(u.nb)("Time")},{width:"9%",text:Object(u.nb)("Modifier")},{width:"12%",text:"".concat(Object(u.nb)("Device")," / ").concat(Object(u.nb)("Version"))},{width:"12%",text:Object(u.nb)("Labels")},{width:"12%",text:""}]:[{width:"43%",text:Object(u.nb)("Description")},{width:"15%",text:Object(u.nb)("Time")},{width:"15%",text:Object(u.nb)("Modifier")},{width:"15%",text:"".concat(Object(u.nb)("Device")," / ").concat(Object(u.nb)("Version"))},{width:"12%",text:""}],n}return Object(n.a)(a,[{key:"render",value:function(){var e=this.props,t=e.isLoading,a=e.errorMsg,i=e.items,n=e.curPerPage,s=e.currentPage,c=e.hasNextPage;return t?Object(C.jsx)(p.a,{}):a?Object(C.jsx)("p",{className:"error mt-6 text-center",children:a}):Object(C.jsxs)(o.a.Fragment,{children:[Object(C.jsxs)("table",{className:"table-hover",children:[Object(C.jsx)("thead",{children:Object(C.jsx)("tr",{children:this.theadData.map((function(e,t){return Object(C.jsx)("th",{width:e.width,children:e.text},t)}))})}),Object(C.jsx)("tbody",{children:i.map((function(e,t){return e.isFirstCommit=1==s&&0==t,e.showDetails=c||t!=i.length-1,Object(C.jsx)(E,{item:e},t)}))})]}),Object(C.jsx)(O.a,{gotoPreviousPage:this.getPreviousPage,gotoNextPage:this.getNextPage,currentPage:s,hasNextPage:c,curPerPage:n,resetPerPage:this.props.resetPerPage})]})}}]),a}(o.a.Component),E=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).handleMouseOver=function(){n.setState({isIconShown:!0})},n.handleMouseOut=function(){n.setState({isIconShown:!1})},n.showCommitDetails=function(e){e.preventDefault(),n.setState({isCommitDetailsDialogOpen:!n.state.isCommitDetailsDialogOpen})},n.toggleCommitDetailsDialog=function(){n.setState({isCommitDetailsDialogOpen:!n.state.isCommitDetailsDialogOpen})},n.editLabel=function(){n.setState({isCommitLabelUpdateDialogOpen:!n.state.isCommitLabelUpdateDialogOpen})},n.toggleLabelEditDialog=function(){n.setState({isCommitLabelUpdateDialogOpen:!n.state.isCommitLabelUpdateDialogOpen})},n.updateLabels=function(e){n.setState({labels:e})},n.state={labels:n.props.item.tags,isIconShown:!1,isCommitLabelUpdateDialogOpen:!1,isCommitDetailsDialogOpen:!1},n}return Object(n.a)(a,[{key:"render",value:function(){var e=this.props.item,t=this.state,a=t.isIconShown,i=t.isCommitLabelUpdateDialogOpen,n=t.isCommitDetailsDialogOpen,s=t.labels,c="";return c=e.email?e.second_parent_id?Object(u.nb)("None"):Object(C.jsx)("a",{href:"".concat(u.kc,"profile/").concat(encodeURIComponent(e.email),"/"),children:e.name}):Object(u.nb)("Unknown"),Object(C.jsxs)(o.a.Fragment,{children:[Object(C.jsxs)("tr",{onMouseOver:this.handleMouseOver,onMouseOut:this.handleMouseOut,children:[Object(C.jsxs)("td",{children:[e.description,e.showDetails&&Object(C.jsx)("a",{href:"#",className:"details",onClick:this.showCommitDetails,children:Object(u.nb)("Details")})]}),Object(C.jsx)("td",{title:m()(e.time).format("LLLL"),children:m()(e.time).format("YYYY-MM-DD")}),Object(C.jsx)("td",{children:c}),Object(C.jsx)("td",{children:e.client_version?"".concat(e.device_name," / ").concat(e.client_version):"API / --"}),I&&Object(C.jsxs)("td",{children:[s.map((function(e,t){return Object(C.jsx)("span",{className:"commit-label",children:e},t)})),"rw"==S&&Object(C.jsx)("span",{className:"attr-action-icon fa fa-pencil-alt ".concat(a?"":"invisible"),title:Object(u.nb)("Edit"),onClick:this.editLabel})]}),Object(C.jsx)("td",{children:"rw"==S&&(e.isFirstCommit?Object(C.jsx)("span",{className:a?"":"invisible",children:Object(u.nb)("Current Version")}):Object(C.jsx)("a",{href:"".concat(u.kc,"repo/").concat(N,"/snapshot/?commit_id=").concat(e.commit_id),className:a?"":"invisible",children:Object(u.nb)("View Snapshot")}))})]}),n&&Object(C.jsx)(f.a,{children:Object(C.jsx)(D.a,{repoID:N,commitID:e.commit_id,commitTime:e.time,toggleDialog:this.toggleCommitDetailsDialog})}),i&&Object(C.jsx)(f.a,{children:Object(C.jsx)(y,{repoID:N,commitID:e.commit_id,commitLabels:s,updateCommitLabels:this.updateLabels,toggleDialog:this.toggleLabelEditDialog})})]})}}]),a}(o.a.Component);b.a.render(Object(C.jsx)(_,{}),document.getElementById("wrapper"))},323:function(e,t,a){"use strict";var i=a(6),n=a(7),s=a(9),c=a(8),r=a(2),o=a.n(r),l=a(4),b=a(13),d=a.n(b),h=a(1),m=a(10),j=a(5),u=a(16),g=(a(523),a(0)),p=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).state={isLoading:!0,errorMsg:""},n}return Object(n.a)(a,[{key:"componentDidMount",value:function(){var e=this,t=this.props,a=t.repoID,i=t.commitID;m.a.getCommitDetails(a,i).then((function(t){e.setState({isLoading:!1,errorMsg:"",commitDetails:t.data})})).catch((function(t){var a=j.a.getErrorMsg(t);e.setState({isLoading:!1,errorMsg:a})}))}},{key:"render",value:function(){var e=this.props,t=e.toggleDialog;e.commitTime;return Object(g.jsxs)(l.x,{isOpen:!0,centered:!0,toggle:t,children:[Object(g.jsx)(l.A,{toggle:t,children:Object(h.nb)("Modification Details")}),Object(g.jsxs)(l.y,{children:[Object(g.jsx)("p",{className:"small",children:d()(this.props.commitTime).format("YYYY-MM-DD HH:mm:ss")}),Object(g.jsx)(O,{data:this.state})]})]})}}]),a}(o.a.Component),O=function(e){Object(s.a)(a,e);var t=Object(c.a)(a);function a(){var e;Object(i.a)(this,a);for(var n=arguments.length,s=new Array(n),c=0;c<n;c++)s[c]=arguments[c];return(e=t.call.apply(t,[this].concat(s))).renderDetails=function(e){for(var t=[{type:"new",title:Object(h.nb)("New files")},{type:"removed",title:Object(h.nb)("Deleted files")},{type:"renamed",title:Object(h.nb)("Renamed or Moved files")},{type:"modified",title:Object(h.nb)("Modified files")},{type:"newdir",title:Object(h.nb)("New directories")},{type:"deldir",title:Object(h.nb)("Deleted directories")}],a=!0,i=0,n=t.length;i<n;i++)if(e[t[i].type].length){a=!1;break}return a?Object(g.jsx)("p",{children:e.cmt_desc}):Object(g.jsx)(o.a.Fragment,{children:t.map((function(t,a){if(e[t.type].length)return Object(g.jsxs)(o.a.Fragment,{children:[Object(g.jsx)("h6",{children:t.title}),Object(g.jsx)("ul",{children:e[t.type].map((function(e,t){return Object(g.jsx)("li",{dangerouslySetInnerHTML:{__html:e},className:"commit-detail-item"},t)}))})]},a)}))})},e}return Object(n.a)(a,[{key:"render",value:function(){var e=this.props.data,t=e.isLoading,a=e.errorMsg,i=e.commitDetails;return t?Object(g.jsx)(u.a,{}):a?Object(g.jsx)("p",{className:"error mt-4 text-center",children:a}):this.renderDetails(i)}}]),a}(o.a.Component);t.a=p},523:function(e,t,a){}},[[1577,1,0]]]);
//# sourceMappingURL=repoHistory.chunk.js.map
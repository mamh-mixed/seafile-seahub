(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[9],{1691:function(t,e,a){a(73),t.exports=a(1832)},1692:function(t,e,a){},1832:function(t,e,a){"use strict";a.r(e);var i=a(48),s=a(3),n=a(4),o=a(6),r=a(7),c=a(2),d=a.n(c),l=a(33),h=a.n(l),j=a(83),b=a(5),m=a(8),u=a(1),O=a(108),p=a(21),f=a(122),g=a(72),x=a(12),v=a.n(x),y=a(110),R=a(326),w=a(329),_=a(328),L=a(200),S=a(0);v.a.locale(window.app.config.lang);var C=function(t){Object(o.a)(a,t);var e=Object(r.a)(a);function a(t){var i;return Object(s.a)(this,a),(i=e.call(this,t)).onMouseEnter=function(){i.setState({active:!0})},i.onMouseLeave=function(){i.setState({active:!1})},i.onItemRestore=function(t){t.preventDefault(),i.props.onItemRestore(i.props.item)},i.state={active:!1},i}return Object(n.a)(a,[{key:"render",value:function(){var t=this.props.item,e=y.a.getUrl({type:"download_historic_file",filePath:u.qb,objID:t.rev_file_id}),a="".concat(u.wc,"profile/").concat(encodeURIComponent(t.creator_email),"/"),i="".concat(u.wc,"repo/").concat(u.yb,"/history/files/?obj_id=").concat(t.rev_file_id,"&commit_id=").concat(t.commit_id,"&p=").concat(b.a.encodePath(u.qb)),s="".concat(u.wc,"repo/text_diff/").concat(u.yb,"/?commit=").concat(t.commit_id,"&p=").concat(b.a.encodePath(u.qb)),n="".concat(u.wc,"repo/").concat(u.yb,"/snapshot/?commit_id=").concat(t.commit_id);return Object(S.jsx)(c.Fragment,{children:Object(S.jsxs)("tr",{onMouseEnter:this.onMouseEnter,onMouseLeave:this.onMouseLeave,className:this.state.active?"tr-highlight":"",children:[Object(S.jsxs)("td",{children:[Object(S.jsx)("span",{children:v()(t.ctime).format("YYYY-MM-DD HH:mm:ss")}),0===this.props.index&&Object(S.jsx)("span",{className:"ml-1",children:Object(u.ub)("(current version)")})]}),Object(S.jsxs)("td",{children:[Object(S.jsx)("img",{className:"avatar",src:t.creator_avatar_url,alt:""})," ",Object(S.jsx)("a",{href:a,target:"_blank",className:"username",children:t.creator_name})]}),Object(S.jsx)("td",{children:b.a.bytesToSize(t.size)}),Object(S.jsx)("td",{children:this.state.active&&Object(S.jsx)(H,{index:this.props.index,downloadUrl:e,viewUrl:i,diffUrl:s,snapshotURL:n,onItemRestore:this.onItemRestore,canDownload:this.props.canDownload,canCompare:this.props.canCompare})})]})})}}]),a}(d.a.Component),H=function(t){Object(o.a)(a,t);var e=Object(r.a)(a);function a(t){var i;return Object(s.a)(this,a),(i=e.call(this,t)).dropdownToggle=function(){i.setState({dropdownOpen:!i.state.dropdownOpen})},i.state={dropdownOpen:!1},i}return Object(n.a)(a,[{key:"render",value:function(){var t=this.props,e=t.index,a=t.downloadUrl,i=t.viewUrl,s=(t.diffUrl,t.snapshotURL),n=t.onItemRestore,o=(t.canCompare,t.canDownload);return Object(S.jsxs)(R.a,{isOpen:this.state.dropdownOpen,toggle:this.dropdownToggle,direction:"down",className:"mx-1 old-history-more-operation",children:[Object(S.jsx)(w.a,{tag:"i",className:"fa fa-ellipsis-v",title:Object(u.ub)("More Operations"),"data-toggle":"dropdown","aria-expanded":this.state.dropdownOpen}),Object(S.jsxs)(_.a,{className:"drop-list",right:!0,children:[0!==e&&Object(S.jsx)("a",{href:"#",onClick:n,children:Object(S.jsx)(L.a,{children:Object(u.ub)("Restore")})}),o&&Object(S.jsx)("a",{href:a,children:Object(S.jsx)(L.a,{children:Object(u.ub)("Download")})}),Object(S.jsx)("a",{href:i,children:Object(S.jsx)(L.a,{children:Object(u.ub)("View")})}),0!=e&&Object(S.jsx)(L.a,{tag:"a",href:s,target:"_blank",children:Object(u.ub)("View Related Snapshot")})]})]})}}]),a}(d.a.PureComponent),N=C,k=(a(204),a(157),a(178),a(1692),function(t){Object(o.a)(a,t);var e=Object(r.a)(a);function a(t){var i;return Object(s.a)(this,a),(i=e.call(this,t)).listNewHistoryRecords=function(t,e){O.a.listFileHistoryRecords(t,1,e).then((function(t){if(!t.data)throw i.setState({isLoading:!1}),Error("There is an error in server.");i.initNewRecords(t.data)}))},i.listOldHistoryRecords=function(t,e){m.a.listOldFileHistoryRecords(t,e).then((function(t){if(!t.data)throw i.setState({isLoading:!1}),Error("There is an error in server.");i.initOldRecords(t.data)}))},i.onScrollHandler=function(t){var e=t.target.clientHeight,a=t.target.scrollHeight,s=e+t.target.scrollTop+1>=a,n=i.state.hasMore;s&&n&&i.reloadMore()},i.reloadMore=function(){if(!i.state.isReloadingData)if(u.Hc){var t=i.state.currentPage+1;i.setState({currentPage:t,isReloadingData:!0}),O.a.listFileHistoryRecords(u.qb,t,u.a).then((function(t){i.updateNewRecords(t.data)}))}else{var e=i.state.nextCommit,a=i.state.filePath,s=i.state.oldFilePath;i.setState({isReloadingData:!0}),s?m.a.listOldFileHistoryRecords(u.yb,s,e).then((function(t){i.updateOldRecords(t.data,s)})):m.a.listOldFileHistoryRecords(u.yb,a,e).then((function(t){i.updateOldRecords(t.data,a)}))}},i.onItemRestore=function(t){var e=t.commit_id,a=t.path;O.a.revertFile(a,e).then((function(t){t.data.success&&(i.setState({isLoading:!0}),i.refershFileList())}))},i.onSearchedClick=function(t){b.a.handleSearchedItemClick(t)},i.state={historyList:[],currentPage:1,hasMore:!1,nextCommit:void 0,filePath:"",oldFilePath:"",isLoading:!0,isReloadingData:!1},i}return Object(n.a)(a,[{key:"componentDidMount",value:function(){u.Hc?this.listNewHistoryRecords(u.qb,u.a):this.listOldHistoryRecords(u.yb,u.qb)}},{key:"initNewRecords",value:function(t){var e=this;if(t.total_count<5)if(t.data.length){var a=t.data[t.data.length-1].commit_id,i=t.data[t.data.length-1].path,s=t.data[t.data.length-1].old_path;i=s||i,m.a.listOldFileHistoryRecords(u.yb,i,a).then((function(a){if(!a.data)throw e.setState({isLoading:!1}),Error("There is an error in server.");e.setState({historyList:t.data.concat(a.data.data.slice(1,a.data.data.length)),isLoading:!1})}))}else m.a.listOldFileHistoryRecords(u.yb,u.qb).then((function(t){if(!t.data)throw e.setState({isLoading:!1}),Error("There is an error in server.");e.setState({historyList:t.data.data,isLoading:!1})}));else this.setState({historyList:t.data,currentPage:t.page,hasMore:t.total_count>u.a*this.state.currentPage,isLoading:!1})}},{key:"initOldRecords",value:function(t){var e=this;t.data.length?this.setState({historyList:t.data,nextCommit:t.next_start_commit,filePath:t.data[t.data.length-1].path,oldFilePath:t.data[t.data.length-1].rev_renamed_old_path,isLoading:!1}):(this.setState({nextCommit:t.next_start_commit}),this.state.nextCommit?m.a.listOldFileHistoryRecords(u.yb,u.qb,this.state.nextCommit).then((function(t){e.initOldRecords(t.data)})):this.setState({isLoading:!1}))}},{key:"updateNewRecords",value:function(t){this.setState({historyList:[].concat(Object(i.a)(this.state.historyList),Object(i.a)(t.data)),currentPage:t.page,hasMore:t.total_count>u.a*this.state.currentPage,isReloadingData:!1})}},{key:"updateOldRecords",value:function(t,e){var a=this;t.data.length?this.setState({historyList:[].concat(Object(i.a)(this.state.historyList),Object(i.a)(t.data)),nextCommit:t.next_start_commit,filePath:t.data[t.data.length-1].path,oldFilePath:t.data[t.data.length-1].rev_renamed_old_path,isReloadingData:!1}):(this.setState({nextCommit:t.next_start_commit}),this.state.nextCommit&&m.a.listOldFileHistoryRecords(u.yb,e,this.state.nextCommit).then((function(t){a.updateOldRecords(t.data,e)})))}},{key:"refershFileList",value:function(){var t=this;u.Hc?O.a.listFileHistoryRecords(u.qb,1,u.a).then((function(e){t.initNewRecords(e.data)})):m.a.listOldFileHistoryRecords(u.yb,u.qb).then((function(e){t.initOldRecords(e.data)}))}},{key:"render",value:function(){var t=this;return Object(S.jsxs)(c.Fragment,{children:[Object(S.jsxs)("div",{id:"header",className:"old-history-header",children:[Object(S.jsx)("div",{className:"logo",children:Object(S.jsx)(f.a,{showCloseSidePanelIcon:!1})}),Object(S.jsx)("div",{className:"toolbar",children:Object(S.jsx)(g.a,{onSearchedClick:this.onSearchedClick})})]}),Object(S.jsx)("div",{id:"main",onScroll:this.onScrollHandler,children:Object(S.jsxs)("div",{className:"old-history-main",children:[Object(S.jsxs)(c.Fragment,{children:[Object(S.jsx)("a",{href:"javascript:window.history.back()",className:"go-back",title:"Back",children:Object(S.jsx)("span",{className:"fas fa-chevron-left"})}),Object(S.jsxs)("h2",{children:[Object(S.jsx)("span",{className:"file-name",children:u.pb})," ",Object(u.ub)("History Versions")]})]}),Object(S.jsxs)(c.Fragment,{children:[Object(S.jsxs)("table",{className:"commit-list",children:[Object(S.jsx)("thead",{children:Object(S.jsxs)("tr",{children:[Object(S.jsx)("th",{width:"40%",children:Object(u.ub)("Time")}),Object(S.jsx)("th",{width:"30%",children:Object(u.ub)("Modifier")}),Object(S.jsx)("th",{width:"25%",children:Object(u.ub)("Size")}),Object(S.jsx)("th",{width:"5%"})]})}),!this.state.isLoading&&Object(S.jsx)("tbody",{children:this.state.historyList.map((function(e,a){return Object(S.jsx)(N,{item:e,index:a,canDownload:u.n,canCompare:u.l,onItemRestore:t.onItemRestore},a)}))})]}),(this.state.isReloadingData||this.state.isLoading)&&Object(S.jsx)(p.a,{}),this.state.nextCommit&&!this.state.isLoading&&!this.state.isReloadingData&&Object(S.jsx)(j.a,{className:"get-more-btn",onClick:this.reloadMore,children:Object(u.ub)("More")})]})]})})]})}}]),a}(d.a.Component));h.a.render(Object(S.jsx)(k,{}),document.getElementById("wrapper"))}},[[1691,1,0]]]);
//# sourceMappingURL=fileHistoryOld.chunk.js.map
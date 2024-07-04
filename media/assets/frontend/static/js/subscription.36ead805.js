"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[41],{94775:function(e,s,t){t.d(s,{Z:function(){return L}});var n=t(15671),a=t(43144),r=t(97326),i=t(60136),o=t(29388),c=t(47313),l=t(68396),d=t(21303),p=t(59743),u=t(76578),m=t(25965),h=t(5684),x=t(42995),g=t(12756),f=t(12213),j=t(7764),v=t(61805),y=t(83854),b=t(35662),N=t(11621),_=function(){function e(){(0,n.Z)(this,e)}return(0,a.Z)(e,[{key:"init",value:function(e){var s=e.server,t=e.username,n=e.password,a=e.token;return this.server=s,this.username=t,this.password=n,this.token=a,this.token&&this.server&&(this.req=b.Z.create({baseURL:this.server,headers:{Authorization:"Token "+this.token}})),this}},{key:"initForSeahubUsage",value:function(e){var s=e.siteRoot,t=e.xcsrfHeaders;if(s&&"/"===s.charAt(s.length-1)){var n=s.substring(0,s.length-1);this.server=n}else this.server=s;return this.req=b.Z.create({headers:{"X-CSRFToken":t}}),this}},{key:"getSubscription",value:function(){var e=this.server+"/api/v2.1/subscription/";return this.req.get(e)}},{key:"getSubscriptionPlans",value:function(e){var s=this.server+"/api/v2.1/subscription/plans/",t={payment_type:e};return this.req.get(s,{params:t})}},{key:"getSubscriptionLogs",value:function(){var e=this.server+"/api/v2.1/subscription/logs/";return this.req.get(e)}}]),e}(),Z=new _,C=N.ZP.load("sfcsrftoken");Z.initForSeahubUsage({siteRoot:v.ze,xcsrfHeaders:C});var T=t(51282),S=(t(54890),t(46417)),w=window.app.pageOptions.isOrgContext,k=function(e){(0,i.Z)(t,e);var s=(0,o.Z)(t);function t(e){var a;return(0,n.Z)(this,t),(a=s.call(this,e)).togglePlan=function(e){a.setState({currentPlan:e},(function(){}))},a.onPay=function(){var e,s,t,n=a.props.paymentType,r=a.state,i=r.currentPlan,o=r.assetQuotaUnitCount,c=r.count;if("paid"===n)t=i.count,e=i.total_amount;else if("extend_time"===n)t=i.count,s=i.asset_quota,e=i.total_amount;else if("add_user"===n)t=c,e=c*i.price_per_user;else{if("buy_quota"!==n)return void l.Z.danger((0,v.ih)("Internal Server Error."));s=o*i.asset_quota_unit,e=o*i.price_per_asset_quota_unit}a.props.onPay(i.plan_id,t,s,e)},a.onCountInputChange=function(e){if(a.state.currentPlan.can_custom_count){var s=e.target.value.replace(/^(0+)|[^\d]+/g,"");s<1?s=1:s>9999&&(s=9999),a.setState({count:s})}},a.onAssetQuotaUnitCountInputChange=function(e){if(a.state.currentPlan.can_custom_asset_quota){var s=e.target.value.replace(/^(0+)|[^\d]+/g,"");s<1?s=1:s>9999&&(s=9999),a.setState({assetQuotaUnitCount:s})}},a.renderPaidOrExtendTime=function(){var e=a.props,s=e.plans,t=e.paymentType,n=a.state.currentPlan,i=0;"extend_time"===t&&(i=n.asset_quota-100);var o=n.total_amount,l=o;return(0,S.jsxs)("div",{className:"d-flex flex-column subscription-container",children:[(0,S.jsx)("span",{className:"subscription-subtitle",children:"\u9009\u62e9\u65b9\u6848"}),(0,S.jsx)("dl",{className:"items-dl",children:s.map((function(e,s){var t=e.plan_id===n.plan_id?"plan-selected":"",i="\uffe5"+e.price_per_user;return w&&(i+="/\u6bcf\u7528\u6237"),(0,S.jsxs)("dd",{className:"plan-description-item ".concat(t),onClick:a.togglePlan.bind((0,r.Z)(a),e),children:[(0,S.jsx)("span",{className:"plan-name",children:e.name}),(0,S.jsx)("span",{className:"plan-description",children:i})]},s)}))}),"extend_time"===t&&i>0&&(0,S.jsxs)(c.Fragment,{children:[(0,S.jsx)("span",{className:"subscription-subtitle",children:"\u589e\u52a0\u7a7a\u95f4"}),(0,S.jsx)("dl",{className:"items-dl",children:(0,S.jsxs)("dd",{className:"order-item order-item-top order-item-bottom subscription-list",children:[(0,S.jsx)("span",{className:"order-into",children:n.asset_quota_unit+"GB x "+i/n.asset_quota_unit}),(0,S.jsx)("span",{className:"order-value",children:"\uffe5"+i/n.asset_quota_unit*n.price_per_asset_quota_unit})]})})]}),(0,S.jsx)("span",{className:"subscription-subtitle",children:"\u65b9\u6848\u6c47\u603b"}),(0,S.jsx)("dl",{className:"items-dl",children:(0,S.jsxs)("div",{children:[(0,S.jsxs)("dd",{className:"order-item order-item-top",children:[(0,S.jsx)("span",{className:"order-into",children:"\u6240\u9009\u65b9\u6848"}),(0,S.jsx)("span",{className:"order-value",children:n.name})]}),w&&(0,S.jsxs)("dd",{className:"order-item",children:[(0,S.jsx)("span",{className:"order-into",children:"\u6210\u5458\u4eba\u6570"}),(0,S.jsx)("span",{className:"order-value",children:n.count+"\u4eba"})]}),(0,S.jsxs)("dd",{className:"order-item",children:[(0,S.jsx)("span",{className:"order-into",children:"\u53ef\u7528\u7a7a\u95f4"}),(0,S.jsx)("span",{className:"order-value",children:"100GB(\u9644\u8d60)"+(i>0?"+"+i+"GB(\u6269\u5145)":"")})]}),(0,S.jsxs)("dd",{className:"order-item order-item-bottom rounded-0",children:[(0,S.jsx)("span",{className:"order-into",children:"\u5230\u671f\u65f6\u95f4"}),(0,S.jsx)("span",{className:"order-value",children:n.new_term_end})]}),(0,S.jsxs)("dd",{className:"order-item order-item-bottom subscription-list",children:[(0,S.jsx)("span",{className:"order-into",children:"\u5b9e\u9645\u652f\u4ed8\u91d1\u989d"}),(0,S.jsxs)("span",{className:"order-price",children:[l!==o&&(0,S.jsx)("span",{style:{fontSize:"small",textDecoration:"line-through",color:"#9a9a9a"},children:"\uffe5"+l}),(0,S.jsx)("span",{children:"\uffe5"+o+" "})]})]})]})}),(0,S.jsx)(d.Z,{className:"subscription-submit",color:"primary",onClick:a.onPay,children:"\u63d0\u4ea4\u8ba2\u5355"})]})},a.renderAddUser=function(){var e=a.state,s=e.currentPlan,t=e.count,n="\u65b0\u589e\u7528\u6237",r=t*s.price_per_user,i=r;return(0,S.jsxs)("div",{className:"d-flex flex-column subscription-container price-version-container-header subscription-add-user",children:[(0,S.jsx)("div",{className:"price-version-container-top"}),(0,S.jsx)("h3",{className:"user-quota-plan-name py-5",children:s.name}),(0,S.jsxs)("span",{className:"py-2 mb-0 text-orange font-500 text-center",children:["\xa5 ",(0,S.jsx)("span",{className:"price-version-plan-price",children:s.price})," "+s.description]}),(0,S.jsxs)(p.Z,{style:{marginBottom:"5px"},className:"user-numbers",children:[(0,S.jsx)(u.Z,{addonType:"prepend",children:(0,S.jsx)(m.Z,{children:n})}),(0,S.jsx)(h.Z,{className:"py-2",placeholder:n,title:n,type:"number",value:t||1,min:"1",max:"9999",disabled:!s.can_custom_count,onChange:a.onCountInputChange})]}),(0,S.jsxs)("span",{className:"py-2 text-orange mb-0 font-500 price-version-plan-whole-price text-center",children:["\u603b\u4ef7 \xa5 "+i,r!==i&&(0,S.jsx)("span",{style:{fontSize:"small",textDecoration:"line-through",color:"#9a9a9a"},children:" \uffe5"+r})]}),(0,S.jsx)("span",{className:"py-2 mb-0 text-lg-size font-500 price-version-plan-valid-day text-center",children:"\u6709\u6548\u671f\u81f3 "+s.new_term_end}),(0,S.jsx)("span",{className:"subscription-notice text-center py-5",children:"\u6ce8\uff1a\u5f53\u6709\u6548\u671f\u5269\u4f59\u5929\u6570\u5c11\u4e8e\u8ba1\u5212\u4e2d\u7684\u65f6\u5019\uff0c\u589e\u52a0\u7528\u6237\u7684\u4ef7\u683c\u6309\u5929\u6765\u8ba1\u7b97"}),(0,S.jsx)(d.Z,{className:"subscription-submit",onClick:a.onPay,color:"primary",children:"\u7acb\u5373\u8d2d\u4e70"})]})},a.renderBuyQuota=function(){var e=a.state,s=e.currentPlan,t=e.assetQuotaUnitCount,n="\u65b0\u589e\u7a7a\u95f4",r=t*s.price_per_asset_quota_unit,i=r;return(0,S.jsxs)("div",{className:"d-flex flex-column subscription-container price-version-container-header subscription-add-space",children:[(0,S.jsx)("div",{className:"price-version-container-top"}),(0,S.jsx)("h3",{className:"user-quota-plan-name py-5",children:s.name}),(0,S.jsxs)("span",{className:"py-2 mb-0 text-orange font-500 text-center",children:["\xa5 ",(0,S.jsx)("span",{className:"price-version-plan-price",children:s.asset_quota_price})," "+s.asset_quota_description]}),(0,S.jsxs)(p.Z,{style:{marginBottom:"5px"},className:"space-quota",children:[(0,S.jsx)(u.Z,{addonType:"prepend",children:(0,S.jsx)(m.Z,{children:(0,S.jsx)("span",{className:"font-500",children:n})})}),(0,S.jsx)(h.Z,{className:"py-2",placeholder:n,title:n,type:"number",value:t||1,min:"1",max:"9999",disabled:!s.can_custom_asset_quota,onChange:a.onAssetQuotaUnitCountInputChange}),(0,S.jsx)(u.Z,{addonType:"append",children:(0,S.jsx)(m.Z,{children:(0,S.jsx)("span",{className:"font-500",children:" x "+s.asset_quota_unit+"GB"})})})]}),(0,S.jsxs)("span",{className:"py-4 text-orange mb-0 font-500 price-version-plan-whole-price text-center",children:["\u603b\u4ef7 \xa5 "+i,r!==i&&(0,S.jsx)("span",{style:{fontSize:"small",textDecoration:"line-through",color:"#9a9a9a"},children:" \uffe5"+r})]}),(0,S.jsx)("span",{className:"py-2 mb-0 text-lg-size font-500 price-version-plan-valid-day text-center",children:"\u6709\u6548\u671f\u81f3 "+s.new_term_end}),(0,S.jsx)("span",{className:"subscription-notice text-center py-5",children:"\u6ce8\uff1a\u5f53\u6709\u6548\u671f\u5269\u4f59\u5929\u6570\u5c11\u4e8e\u8ba1\u5212\u4e2d\u7684\u65f6\u5019\uff0c\u589e\u52a0\u7a7a\u95f4\u7684\u4ef7\u683c\u6309\u5929\u6765\u8ba1\u7b97"}),(0,S.jsx)(d.Z,{className:"subscription-submit",onClick:a.onPay,color:"primary",children:"\u7acb\u5373\u8d2d\u4e70"})]})},a.state={currentPlan:e.plans[0],assetQuotaUnitCount:1,count:1},a}return(0,a.Z)(t,[{key:"render",value:function(){var e=this.props.paymentType;return"paid"===e||"extend_time"===e?this.renderPaidOrExtendTime():"add_user"===e?this.renderAddUser():"buy_quota"===e?this.renderBuyQuota():void l.Z.danger((0,v.ih)("Internal Server Error."))}}]),t}(c.Component),q=function(e){(0,i.Z)(t,e);var s=(0,o.Z)(t);function t(e){var a;return(0,n.Z)(this,t),(a=s.call(this,e)).getPlans=function(){Z.getSubscriptionPlans(a.props.paymentType).then((function(e){a.setState({planList:e.data.plan_list,paymentSourceList:e.data.payment_source_list,isLoading:!1})})).catch((function(e){var s=y.c.getErrorMsg(e);a.setState({isLoading:!1,errorMsg:s})}))},a.onPay=function(e,s,t,n){a.setState({isWaiting:!0});var r=v.xx+"/subscription/pay/?payment_source="+a.state.paymentSourceList[0]+"&payment_type="+a.props.paymentType+"&plan_id="+e+"&total_amount="+n;s&&(r+="&count="+s),t&&(r+="&asset_quota="+t),window.open(r)},a.onReload=function(){window.location.reload()},a.state={isLoading:!0,isWaiting:!1,planList:[],paymentSourceList:[]},a}return(0,a.Z)(t,[{key:"componentDidMount",value:function(){this.getPlans()}},{key:"render",value:function(){var e=this.state,s=e.isLoading,t=e.isWaiting,n=e.planList,a=this.props,r=a.toggleDialog,i=a.paymentTypeTrans,o=a.paymentType,c="paid"===o||"extend_time"===o?{width:"560px",maxWidth:"560px"}:{width:"560px"};return s?(0,S.jsxs)(x.Z,{isOpen:!0,toggle:r,children:[(0,S.jsx)(g.Z,{toggle:r,children:i}),(0,S.jsx)(f.Z,{children:(0,S.jsx)(T.Z,{})})]}):t?(0,S.jsxs)(x.Z,{isOpen:!0,toggle:this.onReload,children:[(0,S.jsx)(g.Z,{toggle:this.onReload,children:i}),(0,S.jsx)(f.Z,{children:(0,S.jsx)("div",{children:"\u662f\u5426\u5b8c\u6210\u4ed8\u6b3e?"})}),(0,S.jsx)(j.Z,{children:(0,S.jsx)("button",{className:"btn btn-outline-primary",onClick:this.onReload,children:"\u662f"})})]}):(0,S.jsxs)(x.Z,{isOpen:!0,toggle:r,style:c,children:[(0,S.jsx)(g.Z,{toggle:r,children:i}),(0,S.jsx)(f.Z,{children:(0,S.jsx)("div",{className:"d-flex justify-content-between",children:(0,S.jsx)(k,{plans:n,onPay:this.onPay,paymentType:this.props.paymentType})})})]})}}]),t}(c.Component),P=function(e){(0,i.Z)(t,e);var s=(0,o.Z)(t);function t(e){var a;return(0,n.Z)(this,t),(a=s.call(this,e)).getSubscription=function(){Z.getSubscription().then((function(e){var s=e.data.subscription,t=e.data.payment_type_list;if(s){var n=s.is_active,r=s.plan;a.setState({isLoading:!1,subscription:s,planName:r.name,userLimit:s.user_limit,assetQuota:n?s.asset_quota:r.asset_quota,termEnd:n?s.term_end:"\u5df2\u8fc7\u671f",paymentTypeList:t})}else a.setState({isLoading:!1,paymentTypeList:t})})).catch((function(e){var s=y.c.getErrorMsg(e);a.setState({isLoading:!1,errorMsg:s})}))},a.toggleDialog=function(){a.setState({isDialogOpen:!a.state.isDialogOpen})},a.togglePaymentType=function(e){a.setState({currentPaymentType:e}),a.toggleDialog()},a.paymentTypeTransMap={paid:"\u7acb\u5373\u8d2d\u4e70",extend_time:"\u7acb\u5373\u7eed\u8d39",add_user:"\u589e\u52a0\u7528\u6237",buy_quota:"\u589e\u52a0\u7a7a\u95f4"},a.state={isLoading:!0,errorMsg:"",isDialogOpen:!1,planName:a.props.isOrgContext?"\u56e2\u961f\u7248":"\u4e2a\u4eba\u7248",userLimit:20,assetQuota:1,termEnd:"\u957f\u671f",subscription:null,paymentTypeList:[],currentPaymentType:"",errorMsgCode:""},a}return(0,a.Z)(t,[{key:"componentDidMount",value:function(){this.getSubscription()}},{key:"render",value:function(){var e=this,s=this.state,t=s.isLoading,n=s.errorMsg,a=s.planName,r=s.userLimit,i=s.assetQuota,o=s.termEnd,l=s.isDialogOpen,d=s.paymentTypeList,p=s.currentPaymentType;return t?(0,S.jsx)(T.Z,{}):n?(0,S.jsx)("p",{className:"text-center mt-8 error",children:n}):(0,S.jsxs)(c.Fragment,{children:[(0,S.jsxs)("div",{className:"content position-relative",onScroll:this.props.handleContentScroll,children:[(0,S.jsxs)("div",{id:"current-plan",className:"subscription-info",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u5f53\u524d\u7248\u672c"}),(0,S.jsx)("p",{className:"mb-2",children:a})]}),this.props.isOrgContext&&(0,S.jsxs)("div",{id:"user-limit",className:"subscription-info",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u7528\u6237\u6570\u9650\u5236"}),(0,S.jsx)("p",{className:"mb-2",children:r})]}),(0,S.jsxs)("div",{id:"asset-quota",className:"subscription-info",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u7a7a\u95f4"}),(0,S.jsx)("p",{className:"mb-2",children:i?i+"GB":"1GB"})]}),(0,S.jsxs)("div",{id:"current-subscription-period",className:"subscription-info",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u8ba2\u9605\u6709\u6548\u671f"}),(0,S.jsx)("p",{className:"mb-2",children:o})]}),(0,S.jsxs)("div",{id:"product-price",className:"subscription-info",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u4e91\u670d\u52a1\u4ed8\u8d39\u65b9\u6848"}),(0,S.jsx)("p",{className:"mb-2",children:(0,S.jsx)("a",{rel:"noopener noreferrer",target:"_blank",href:"https://www.seafile.com/seafile-docs/home/",children:"\u67e5\u770b\u8be6\u60c5"})})]}),d.map((function(s,t){var n=e.paymentTypeTransMap[s];return(0,S.jsx)("button",{className:"btn btn-outline-primary mr-4",onClick:e.togglePaymentType.bind(e,s),children:n},t)})),!this.state.subscription&&(0,S.jsxs)("div",{id:"sales-consultant",className:"subscription-info mt-6",children:[(0,S.jsx)("h3",{className:"subscription-info-heading",children:"\u9500\u552e\u54a8\u8be2"}),(0,S.jsx)("img",{className:"mb-2",src:"/media/img/qr-sale.png",alt:"",width:"112"}),(0,S.jsx)("p",{className:"mb-2",children:"\u5fae\u4fe1\u626b\u7801\u8054\u7cfb\u9500\u552e"})]})]}),l&&(0,S.jsx)(q,{paymentType:p,paymentTypeTrans:this.paymentTypeTransMap[p],isOrgContext:this.props.isOrgContext,toggleDialog:this.toggleDialog})]})}}]),t}(c.Component),L=P},43862:function(e,s,t){var n=t(15671),a=t(43144),r=t(60136),i=t(29388),o=t(47313),c=t(46417),l=function(e){(0,r.Z)(t,e);var s=(0,i.Z)(t);function t(){return(0,n.Z)(this,t),s.apply(this,arguments)}return(0,a.Z)(t,[{key:"render",value:function(){var e=this;return(0,c.jsx)("ul",{className:"nav flex-column user-setting-nav",children:this.props.data.map((function(s,t){return s.show?(0,c.jsx)("li",{className:"nav-item".concat(e.props.curItemID==s.href.substr(1)?" active":""),children:(0,c.jsx)("a",{className:"nav-link",href:s.href,children:s.text})},t):null}))})}}]),t}(o.Component);s.Z=l},93176:function(e,s,t){var n=t(15671),a=t(43144),r=t(60136),i=t(29388),o=t(47313),c=t(1168),l=t(61805),d=t(43862),p=t(93190),u=t(29619),m=t(94775),h=(t(98391),t(53379),t(69552),t(46417)),x=function(e){(0,r.Z)(t,e);var s=(0,i.Z)(t);function t(e){var a;return(0,n.Z)(this,t),(a=s.call(this,e)).handleContentScroll=function(e){var s=e.target.scrollTop,t=a.sideNavItems.filter((function(e,t){return e.show&&document.getElementById(e.href.substr(1)).offsetTop-45<s}));t.length&&a.setState({curItemID:t[t.length-1].href.substr(1)})},a.sideNavItems=[{show:!0,href:"#current-plan",text:"\u5f53\u524d\u7248\u672c"},{show:!0,href:"#asset-quota",text:"\u7a7a\u95f4"},{show:!0,href:"#current-subscription-period",text:"\u8ba2\u9605\u6709\u6548\u671f"},{show:!0,href:"#product-price",text:"\u4e91\u670d\u52a1\u4ed8\u8d39\u65b9\u6848"}],a.state={curItemID:a.sideNavItems[0].href.substr(1)},a}return(0,a.Z)(t,[{key:"render",value:function(){var e=l.j1.startsWith("http")?l.j1:l.si+l.j1;return(0,h.jsxs)("div",{className:"h-100 d-flex flex-column",children:[(0,h.jsxs)("div",{className:"top-header d-flex justify-content-between",children:[(0,h.jsx)("a",{href:l.ze,children:(0,h.jsx)("img",{src:e,height:l.AN,width:l.Bv,title:l.y7,alt:"logo"})}),(0,h.jsxs)("div",{className:"common-toolbar",children:[(0,h.jsx)(u.Z,{}),(0,h.jsx)(p.Z,{})]})]}),(0,h.jsxs)("div",{className:"flex-auto d-flex o-hidden",children:[(0,h.jsx)("div",{className:"side-panel o-auto",children:(0,h.jsx)(d.Z,{data:this.sideNavItems,curItemID:this.state.curItemID})}),(0,h.jsxs)("div",{className:"main-panel d-flex flex-column",children:[(0,h.jsx)("h2",{className:"heading",children:"\u4ed8\u8d39\u7ba1\u7406"}),(0,h.jsx)(m.Z,{isOrgContext:!1,handleContentScroll:this.handleContentScroll})]})]})]})}}]),t}(o.Component);c.render((0,h.jsx)(x,{}),document.getElementById("wrapper"))},69552:function(){}},function(e){e.O(0,[351],(function(){return s=93176,e(e.s=s);var s}));e.O()}]);
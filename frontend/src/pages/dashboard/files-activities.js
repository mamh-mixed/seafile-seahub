import React, { Component, Fragment } from 'react';
import { Link } from '@gatsbyjs/reach-router';
import PropTypes from 'prop-types';
import moment from 'moment';
import { seafileAPI } from '../../utils/seafile-api';
import { gettext, siteRoot, serviceURL } from '../../utils/constants';
import { Utils } from '../../utils/utils';
import Loading from '../../components/loading';
import Activity from '../../models/activity';
import ListCreatedFileDialog from '../../components/dialog/list-created-files-dialog';
import ModalPortal from '../../components/modal-portal';

import '../../css/files-activities.css';

moment.locale(window.app.config.lang);

const contentPropTypes = {
  isLoadingMore: PropTypes.bool.isRequired,
  items: PropTypes.array.isRequired,
};

class FileActivitiesContent extends Component {

  render() {
    const isDesktop = Utils.isDesktop();
    let { items, isLoadingMore } = this.props;

    const desktopThead = (
      <thead>
        <tr>
          <th width="8%">{/* avatar */}</th>
          <th width="15%">{gettext('User')}</th>
          <th width="20%">{gettext('Operation')}</th>
          <th width="37%">{gettext('File')} / {gettext('Library')}</th>
          <th width="20%">{gettext('Time')}</th>
        </tr>
      </thead>
    );

    const mobileThead = (
      <thead>
        <tr>
          <th width="15%"></th>
          <th width="53%"></th>
          <th width="32%"></th>
        </tr>
      </thead>
    );

    return (
      <Fragment>
        <table className="table-hover table-thead-hidden">
          {isDesktop ? desktopThead : mobileThead}
          <tbody>
            {items.map((item, index) => {
              return (
                <ActivityItem
                  key={index}
                  isDesktop={isDesktop}
                  item={item}
                  index={index}
                  items={items}
                />
              );
            })}
          </tbody>
        </table>
        {isLoadingMore ? <span className="loading-icon loading-tip"></span> : ''}
      </Fragment>
    );
  }
}

FileActivitiesContent.propTypes = contentPropTypes;

const activityPropTypes = {
  item: PropTypes.object.isRequired,
  index: PropTypes.number.isRequired,
  items: PropTypes.array.isRequired,
  isDesktop: PropTypes.bool.isRequired,
};

class ActivityItem extends Component {

  constructor(props) {
    super(props);
    this.state = {
      isListCreatedFiles: false,
    };
  }

  onListCreatedFilesToggle = () => {
    this.setState({
      isListCreatedFiles: !this.state.isListCreatedFiles,
    });
  };

  render() {
    const isDesktop = this.props.isDesktop;
    let {item, index, items} = this.props;
    let op, details, moreDetails = false;
    let userProfileURL = `${siteRoot}profile/${encodeURIComponent(item.author_email)}/`;

    let libURL = siteRoot + 'library/' + item.repo_id + '/' + encodeURIComponent(item.repo_name) + '/';
    let libLink = <a href={libURL}>{item.repo_name}</a>;
    let smallLibLink = <a className="small text-secondary" href={libURL}>{item.repo_name}</a>;

    if (item.obj_type == 'repo') {
      switch(item.op_type) {
        case 'create':
          op = gettext('Created library');
          details = libLink;
          break;
        case 'rename':
          op = gettext('Renamed library');
          details = <span>{item.old_repo_name} => {libLink}</span>;
          break;
        case 'delete':
          op = gettext('Deleted library');
          details = item.repo_name;
          break;
        case 'recover':
          op = gettext('Restored library');
          details = libLink;
          break;
        case 'clean-up-trash':
          op = gettext('Cleaned trash');
          if (item.days == 0) {
            details = gettext('Removed all items from trash.');
          } else {
            details = gettext('Removed items older than {n} days from trash.').replace('{n}', item.days);
          }
          moreDetails = true;
          break;
      }
    } else if (item.obj_type == 'draft') {
      let fileURL = `${siteRoot}lib/${item.repo_id}/file${Utils.encodePath(item.path)}`;
      let fileLink = <a href={fileURL} target="_blank" rel="noreferrer">{item.name}</a>;
      op = gettext('Publish draft');
      details = fileLink;
      moreDetails = true;
    } else if (item.obj_type == 'files') {
      let fileURL = `${siteRoot}lib/${item.repo_id}/file${Utils.encodePath(item.path)}`;
      if (item.name.endsWith('(draft).md')) {
        fileURL = serviceURL + '/drafts/' + item.draft_id + '/';
      }
      let fileLink = `<a href=${fileURL} target="_blank">${item.name}</a>`;
      if (item.name.endsWith('(draft).md') && !item.draft_id) {
        fileLink = item.name;
      }
      let fileCount = item.createdFilesCount - 1;
      let firstLine = gettext('{file} and {n} other files')
        .replace('{file}', fileLink)
        .replace('{n}', fileCount);
      op = gettext('Created {n} files').replace('{n}', item.createdFilesCount);
      details = (
        <Fragment>
          <p className="m-0 d-inline" dangerouslySetInnerHTML={{__html: firstLine}}></p>
          {isDesktop && <button type="button" onClick={this.onListCreatedFilesToggle} className="activity-details text-secondary ml-2 border-0 p-0 bg-transparent">{gettext('details')}</button>}
        </Fragment>
      );
      moreDetails = true;
    } else if (item.obj_type == 'file') {
      const isDraft = item.name.endsWith('(draft).md');
      const fileURL = isDraft ? serviceURL + '/drafts/' + item.draft_id + '/' :
        `${siteRoot}lib/${item.repo_id}/file${Utils.encodePath(item.path)}`;
      let fileLink = <a href={fileURL} target="_blank" rel="noreferrer">{item.name}</a>;
      if (isDraft && !item.draft_id) {
        fileLink = item.name;
      }
      switch (item.op_type) {
        case 'create':
          op = isDraft ? gettext('Created draft') : gettext('Created file');
          details = fileLink;
          moreDetails = true;
          break;
        case 'delete':
          op = isDraft ? gettext('Deleted draft') : gettext('Deleted file');
          details = item.name;
          moreDetails = true;
          break;
        case 'recover':
          op = gettext('Restored file');
          details = fileLink;
          moreDetails = true;
          break;
        case 'rename':
          op = gettext('Renamed file');
          details = <span>{item.old_name} => {fileLink}</span>;
          moreDetails = true;
          break;
        case 'move':
          // eslint-disable-next-line
          const filePathLink = <a href={fileURL}>{item.path}</a>;
          op = gettext('Moved file');
          details = <span>{item.old_path} => {filePathLink}</span>;
          moreDetails = true;
          break;
        case 'edit': // update
          op = isDraft ? gettext('Updated draft') : gettext('Updated file');
          details = fileLink;
          moreDetails = true;
          break;
      }
    } else { // dir
      let dirURL = siteRoot + 'library/' + item.repo_id + '/' + encodeURIComponent(item.repo_name) + Utils.encodePath(item.path);
      let dirLink = <a href={dirURL} target="_blank" rel="noreferrer">{item.name}</a>;
      switch (item.op_type) {
        case 'create':
          op = gettext('Created folder');
          details = dirLink;
          moreDetails = true;
          break;
        case 'delete':
          op = gettext('Deleted folder');
          details = item.name;
          moreDetails = true;
          break;
        case 'recover':
          op = gettext('Restored folder');
          details = dirLink;
          moreDetails = true;
          break;
        case 'rename':
          op = gettext('Renamed folder');
          details = <span>{item.old_name} => {dirLink}</span>;
          moreDetails = true;
          break;
        case 'move':
          // eslint-disable-next-line
          const dirPathLink = <a href={dirURL}>{item.path}</a>;
          op = gettext('Moved folder');
          details = <span>{item.old_path} => {dirPathLink}</span>;
          moreDetails = true;
          break;
      }
    }

    let isShowDate = true;
    if (index > 0) {
      let lastEventTime = items[index - 1].time;
      isShowDate = moment(item.time).isSame(lastEventTime, 'day') ? false : true;
    }

    return (
      <Fragment>
        {isShowDate &&
          <tr>
            <td colSpan={isDesktop ? 5 : 3} className="border-top-0">{moment(item.time).format('YYYY-MM-DD')}</td>
          </tr>
        }
        {isDesktop ? (
          <tr>
            <td className="text-center">
              <img src={item.avatar_url} alt="" width="32" height="32" className="avatar" />
            </td>
            <td>
              <a href={userProfileURL}>{item.author_name}</a>
            </td>
            <td>{op}</td>
            <td>
              {details}
              {moreDetails && <br /> }
              {moreDetails && smallLibLink}
            </td>
            <td className="text-secondary">
              <time datetime={item.time} is="relative-time" title={moment(item.time).format('llll')}>{moment(item.time).fromNow()}</time>
            </td>
          </tr>
        ) : (
          <tr>
            <td className="text-center align-top">
              <img src={item.avatar_url} alt="" width="32" height="32" className="avatar" />
            </td>
            <td>
              <a href={userProfileURL}>{item.author_name}</a>
              <p className="m-0 text-secondary">{op}</p>
              {details}
            </td>
            <td className="text-right align-top">
              <span className="text-secondary mobile-activity-time">
                <time datetime={item.time} is="relative-time" title={moment(item.time).format('llll')}>{moment(item.time).fromNow()}</time>
              </span>
              {moreDetails && <br /> }
              {moreDetails && libLink}
            </td>
          </tr>
        )}
        {this.state.isListCreatedFiles &&
          <ModalPortal>
            <ListCreatedFileDialog
              activity={item}
              toggleCancel={this.onListCreatedFilesToggle}
            />
          </ModalPortal>
        }
      </Fragment>
    );
  }
}

ActivityItem.propTypes = activityPropTypes;

class FilesActivities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      errorMsg: '',
      isFirstLoading: true,
      isLoadingMore: false,
      currentPage: 1,
      hasMore: true,
      items: [],
      itemsForRender: [],
      showSingleAuthorRecords: false,
      activityAuthors: [],
      showActivityAuthorsPopover: false,
    };
    this.avatarSize = 72;
    this.curPathList = [];
    this.oldPathList = [];
  }

  componentDidMount() {
    let currentPage = this.state.currentPage;
    seafileAPI.listActivities(currentPage, this.avatarSize).then(res => {

      // {"events":[...]}
      let events = this.mergePublishEvents(res.data.events);
      events = this.mergeFileCreateEvents(events);

      // get all authors
      let uniqueSet = new Set();
      let activityAuthors = [];
      events.forEach((item) => {
	if (!uniqueSet.has(item.author_email)) {
          uniqueSet.add(item.author_email);
          item.isSelected = false;
          activityAuthors.push(item);
	}
      });

      this.setState({
        items: events,
        itemsForRender: events,
        activityAuthors: activityAuthors,
        currentPage: currentPage + 1,
        isFirstLoading: false,
        hasMore: true,
      });
      if (this.state.itemsForRender.length < 25) {
        this.getMore();
      }
    }).catch(error => {
      this.setState({
        isFirstLoading: false,
        errorMsg: Utils.getErrorMsg(error, true) // true: show login tip if 403
      });
    });
  }

  mergePublishEvents = (events) => {
    events.forEach((item) => {
      if (item.op_type === 'publish') {
        this.curPathList.push(item.path);
        this.oldPathList.push(item.old_path);
      }
    });
    let actuallyEvents = [];
    for (var i = 0; i < events.length; i++) {
      if (events[i].obj_type === 'file') {
        if (events[i].op_type === 'delete' && this.oldPathList.includes(events[i].path)) {
          this.oldPathList.splice(this.oldPathList.indexOf(events[i].path), 1);
        } else if (events[i].op_type === 'edit' && this.curPathList.includes(events[i].path)) {
          this.curPathList.splice(this.curPathList.indexOf(events[i].path), 1);
        } else if (events[i].op_type === 'rename' && this.oldPathList.includes(events[i].old_path)) {
          this.oldPathList.splice(this.oldPathList.indexOf(events[i].old_path), 1);
        } else {
          actuallyEvents.push(events[i]);
        }
      } else {
        actuallyEvents.push(events[i]);
      }
    }
    return actuallyEvents;
  };

  mergeFileCreateEvents = (events) => {
    let actuallyEvents = [];
    let multiFilesActivity = null;
    for (var i = 0; i < events.length; i++) {
      let isFulfilCondition = events[i].obj_type === 'file' &&
                              events[i].op_type === 'create' &&
                              events[i + 1] &&
                              events[i + 1].obj_type === 'file' &&
                              events[i + 1].op_type === 'create' &&
                              events[i + 1].repo_name === events[i].repo_name &&
                              events[i + 1].author_email === events[i].author_email;
      if (multiFilesActivity != null) {
        multiFilesActivity.createdFilesCount++;
        multiFilesActivity.createdFilesList.push(events[i]);
        if (isFulfilCondition) {
          continue;
        } else {
          actuallyEvents.push(multiFilesActivity);
          multiFilesActivity = null;
        }
      } else {
        if (isFulfilCondition) {
          multiFilesActivity = new Activity(events[i]);
          multiFilesActivity.obj_type = 'files';
          multiFilesActivity.createdFilesCount++;
          multiFilesActivity.createdFilesList.push(events[i]);
        } else {
          actuallyEvents.push(events[i]);
        }
      }
    }
    return actuallyEvents;
  };

  getMore() {
    let currentPage = this.state.currentPage;
    seafileAPI.listActivities(currentPage, this.avatarSize).then(res => {
      // {"events":[...]}
      let events = this.mergePublishEvents(res.data.events);
      events = this.mergeFileCreateEvents(events);

      // merge new authors
      let uniqueSet = new Set();
      this.state.activityAuthors.forEach((item) => {
	if (!uniqueSet.has(item.author_email)) {
          uniqueSet.add(item.author_email);
	}
      });
      let newActivityAuthors = [];
      events.forEach((item) => {
	if (!uniqueSet.has(item.author_email)) {
          uniqueSet.add(item.author_email);
          item.isSelected = false;
          newActivityAuthors.push(item);
	}
      });

      // check if only need to show selected author's record
      let newItemsForRender = []
      if (this.state.showSingleAuthorRecords) {
        let authorEmail = this.state.itemsForRender[0].author_email;
        events.forEach((item) => {
          if (item.author_email === authorEmail) {
            newItemsForRender.push(item);
          }
        });
      } else {
        newItemsForRender = events;
      }

      this.setState({
        isLoadingMore: false,
        items: [...this.state.items, ...events],
        itemsForRender: [...this.state.itemsForRender, ...newItemsForRender],
        activityAuthors: [...this.state.activityAuthors, ...newActivityAuthors],
        currentPage: currentPage + 1,
        hasMore: res.data.events.length === 0 ? false : true
      });
      if (this.state.itemsForRender.length < 25 && this.state.hasMore) {
        this.getMore();
      }
    }).catch(error => {
      this.setState({
        isLoadingMore: false,
        errorMsg: Utils.getErrorMsg(error, true) // true: show login tip if 403
      });
    });
  }

  handleScroll = (event) => {
    if (!this.state.isLoadingMore && this.state.hasMore) {
      const clientHeight = event.target.clientHeight;
      const scrollHeight = event.target.scrollHeight;
      const scrollTop    = event.target.scrollTop;
      const isBottom = (clientHeight + scrollTop + 1 >= scrollHeight);
      if (isBottom) { // scroll to the bottom
        this.setState({isLoadingMore: true}, () => {
          this.getMore();
        });
      }
    }
  };

  toggleActivityAuthorsPopover = (state) => {
    if (state === 'open') {
      this.setState({
        showActivityAuthorsPopover: true
      });
    } else {
      this.setState({
        showActivityAuthorsPopover: false
      });
    }
  };

  showRecordsByAuthor = (authorEmail) => {
    if (authorEmail === "all") {
      let allItems = this.state.items;
      let activityAuthors = this.state.activityAuthors.map(item => {
        item.isSelected = false;
        return item;
      });
      this.setState({
        showSingleAuthorRecords: false,
        itemsForRender: allItems,
        activityAuthors: activityAuthors,
      });
    } else {
      let itemsForRender = []
      this.state.items.forEach((item) => {
        if (item.author_email === authorEmail) {
          itemsForRender.push(item);
        }
      });
      let activityAuthors = this.state.activityAuthors.map(item => {
        item.isSelected = item.author_email === authorEmail ? true : false;
        return item;
      });
      this.setState({
        showSingleAuthorRecords: true,
        itemsForRender: itemsForRender,
        activityAuthors: activityAuthors,
      });
    }
  };

  render() {

    return (
      <div className="main-panel-center">
        <div className="cur-view-container" id="activities">
          <div className="cur-view-path">
            <Fragment>
              <div>
                <ul className="nav">
                  <li className="nav-item">
                  <Link to={`${siteRoot}dashboard/`} className="nav-link active">{gettext('ALL Activities')}</Link>
                  </li>
                  <li className="nav-item">
                  <Link to={`${siteRoot}my-dashboard/`} className="nav-link">{gettext('My Activities')}</Link>
                  </li>
                </ul>
              </div>
              <div className="path-tool">
                <a href="#"
                  className="sf2-icon-user2 action-icon group-top-action-icon"
                  title={gettext('Authors')}
                  onClick={() => this.toggleActivityAuthorsPopover('open')}>
                </a>
                {this.state.showActivityAuthorsPopover &&
                <div className="sf-popover" id="group-members-popover">
                  <div className="sf-popover-hd sf-popover-title group-member-list-header">
                    <span>{gettext('Authors')}</span>
                    <a href="#" className="sf-popover-close js-close sf2-icon-x1 action-icon"
                      onClick={this.toggleActivityAuthorsPopover}></a>
                  </div>
                  <div className="sf-popover-con">
                    <ul className="sf-popover-list group-member-list">
                      <li>
                        <a href="#" className="sf-popover-item user-item d-flex" onClick={this.showRecordsByAuthor.bind(this, "all")}>
                          <span className="group-member-name">{gettext('All Authors')}</span>
                        </a>
                      </li>
                      {this.state.activityAuthors.map((item, index) => {
                        return (
                          <li key={index} className={item.isSelected ? "tr-active" : ""}>
                            <a href="#" className="sf-popover-item user-item d-flex" onClick={this.showRecordsByAuthor.bind(this, item.author_email)}>
                              <img src={item.avatar_url} className="group-member-avatar avatar"/>
                              <span className="group-member-name">{item.author_name}</span>
                              {item.isSelected && <span className="sf2-icon-tick" style={{ position: 'absolute', right: '40px' }}></span>}
                            </a>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                </div>}
              </div>
            </Fragment>
          </div>
          <div className="cur-view-content d-block" onScroll={this.handleScroll}>
            {this.state.isFirstLoading && <Loading />}
            {(!this.state.isFirstLoading && this.state.errorMsg) &&
              <p className="error text-center">{this.state.errorMsg}</p>
            }
            {!this.state.isFirstLoading &&
              <FileActivitiesContent items={this.state.itemsForRender} isLoadingMore={this.state.isLoadingMore}/>
            }
          </div>
        </div>
      </div>
    );
  }
}

export default FilesActivities;

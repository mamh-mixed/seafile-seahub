import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import { gettext } from '../../utils/constants';
import CommonToolbar from '../../components/toolbar/common-toolbar';
import ViewFileToolbar from '../../components/toolbar/view-file-toolbar';

const propTypes = {
  isViewFile: PropTypes.bool.isRequired,
  filePermission: PropTypes.string,
  fileTags: PropTypes.array.isRequired,
  onFileTagChanged: PropTypes.func.isRequired,  // for file-view-toolbar
  // side-panel
  onSideNavMenuClick: PropTypes.func.isRequired,
  // mutiple-dir
  isDirentSelected: PropTypes.bool.isRequired,
  repoID: PropTypes.string.isRequired,
  repoTags: PropTypes.array.isRequired,
  path: PropTypes.string.isRequired,
  selectedDirentList: PropTypes.array.isRequired,
  onItemsMove: PropTypes.func.isRequired,
  onItemsCopy: PropTypes.func.isRequired,
  onItemsDelete: PropTypes.func.isRequired,
  // dir
  direntList: PropTypes.array.isRequired,
  repoName: PropTypes.string.isRequired,
  repoEncrypted: PropTypes.bool.isRequired,
  isGroupOwnedRepo: PropTypes.bool.isRequired,
  userPerm: PropTypes.string.isRequired,
  showShareBtn: PropTypes.bool.isRequired,
  enableDirPrivateShare: PropTypes.bool.isRequired,
  onAddFile: PropTypes.func.isRequired,
  onAddFolder: PropTypes.func.isRequired,
  onUploadFile: PropTypes.func.isRequired,
  onUploadFolder: PropTypes.func.isRequired,
  // view-mode
  currentMode: PropTypes.string.isRequired,
  switchViewMode: PropTypes.func.isRequired,
  // search
  onSearchedClick: PropTypes.func.isRequired,
  isRepoOwner: PropTypes.bool.isRequired,
  // selected menu
  onFilesTagChanged: PropTypes.func.isRequired, // for mutiple select toolbar
  updateDirent: PropTypes.func.isRequired,
  unSelectDirent: PropTypes.func,
  currentRepoInfo: PropTypes.object,
  onItemRename: PropTypes.func,
  showDirentDetail: PropTypes.func,
};

class LibContentToolbar extends React.Component {

  render() {

    if (this.props.isViewFile) {
      return (
        <Fragment>
          <div className="cur-view-toolbar">
            <span className="sf2-icon-menu hidden-md-up d-md-none side-nav-toggle" title={gettext('Side Nav Menu')} onClick={this.props.onSideNavMenuClick}></span>
            <ViewFileToolbar
              path={this.props.path}
              repoID={this.props.repoID}
              userPerm={this.props.userPerm}
              repoEncrypted={this.props.repoEncrypted}
              enableDirPrivateShare={this.props.enableDirPrivateShare}
              isGroupOwnedRepo={this.props.isGroupOwnedRepo}
              filePermission={this.props.filePermission}
              fileTags={this.props.fileTags}
              onFileTagChanged={this.props.onFileTagChanged}
              showShareBtn={this.props.showShareBtn}
              repoTags={this.props.repoTags}
            />
          </div>
          <CommonToolbar
            isLibView={true}
            repoID={this.props.repoID}
            repoName={this.props.repoName}
            onSearchedClick={this.props.onSearchedClick}
            searchPlaceholder={gettext('Search files')}
          />
        </Fragment>
      );
    }

    return (
      <Fragment>
        <div className="cur-view-toolbar">
          <span className="sf2-icon-menu hidden-md-up d-md-none side-nav-toggle" title={gettext('Side Nav Menu')} onClick={this.props.onSideNavMenuClick}></span>
        </div>
        <CommonToolbar
          isLibView={true}
          repoID={this.props.repoID}
          repoName={this.props.repoName}
          currentRepoInfo={this.props.currentRepoInfo}
          onSearchedClick={this.props.onSearchedClick}
          searchPlaceholder={gettext('Search files')}
        />
      </Fragment>
    );
  }
}

LibContentToolbar.propTypes = propTypes;

export default LibContentToolbar;

;; -*- lisp-version: "6.1 [Windows] (Oct 11, 2001 19:31)"; common-graphics: "1.389.2.67.2.24"; -*-

(in-package :common-graphics-user)

(defpackage :common-lisp-user (:export))

(define-project :name :ans
  :application-type (intern "Standard EXE" (find-package :keyword))
  :modules (list (make-instance 'module :name "config")
                 (make-instance 'module :name "ans"))
  :projects nil
  :libraries nil
  :distributed-files nil
  :project-package-name :common-lisp-user
  :main-form nil
  :compilation-unit t
  :verbose nil
  :runtime-modules '(:cg :drag-and-drop :lisp-widget
                     :multi-picture-button :common-control
                     :edit-in-place :outline :grid :group-box
                     :header-control :progress-indicator-control
                     :common-status-bar :tab-control :trackbar-control
                     :up-down-control :dde :mci :carets :hotspots
                     :menu-selection :choose-list :directory-list
                     :color-dialog :find-dialog :font-dialog
                     :string-dialog :yes-no-list-dialog
                     :list-view-control :rich-edit :drawable :ole :www
                     :aclwin302)
  :help-file-module (make-instance 'build-module :name "")
  :splash-file-module (make-instance 'build-module :name "")
  :icon-file-module (make-instance 'build-module :name "")
  :include-flags '(:compiler :top-level :local-name-info)
  :build-flags '(:exit-after-build :allow-debug :purify)
  :autoload-warning t
  :full-recompile-for-runtime-conditionalizations nil
  :default-command-line-arguments "+cm +t \"Initializing\""
  :old-space-size 256000
  :new-space-size 6144
  :runtime-build-option :standard
  :setcmd-path nil
  :on-initialization 'default-init-function
  :on-restart 'do-default-restart)

;; End of Project Definition

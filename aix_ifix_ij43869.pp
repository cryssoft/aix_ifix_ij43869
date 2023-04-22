#
#  2023/02/24 - cp - Added some of the b, c, and d spins and matrix of vulnerable
#		versions.  IBM is making this tougher and tougher.
#
#-------------------------------------------------------------------------------
#
#  From Advisory.asc:
#
#    For kernel:
#
#    AIX Level APAR     Availability  SP        KEY         PRODUCT(S)
#    -----------------------------------------------------------------
#    7.1.5     IJ43967  **            SP11      key_w_apar  kernel
#    7.2.5     IJ43869  **            SP06      key_w_apar  kernel
#    7.3.0     IJ43875  **            SP03      key_w_apar  kernel
#    7.3.1     IJ44594  **            SP02      key_w_apar  kernel
#
#    VIOS Level APAR    Availability  SP        KEY         PRODUCT(S)
#    -----------------------------------------------------------------
#    3.1.2      IJ43995 **            3.1.2.50  key_w_apar  kernel
#    3.1.3      IJ43869 **            3.1.3.30  key_w_apar  kernel
#    3.1.4      IJ43869 **            3.1.4.20  key_w_apar  kernel
#
#    For kernel:
#
#    AIX Level  Interim Fix (*.Z)         KEY        PRODUCT(S)
#    ----------------------------------------------------------
#    7.1.5.8    IJ43967m8a.221110.epkg.Z  key_w_fix  kernel
#    7.1.5.9    IJ43967m9a.221102.epkg.Z  key_w_fix  kernel
#    7.1.5.9    IJ43967m9b.221111.epkg.Z  key_w_fix  kernel
#    7.1.5.10   IJ43967mAa.221024.epkg.Z  key_w_fix  kernel
#|   7.2.5.3    IJ43869m3c.230216.epkg.Z  key_w_fix  kernel <<-- covered here
#|   7.2.5.3    IJ43869m3d.230216.epkg.Z  key_w_fix  kernel
#|   7.2.5.4    IJ43869m4b.230216.epkg.Z  key_w_fix  kernel <<-- covered here
#|   7.2.5.5    IJ43869m5b.230216.epkg.Z  key_w_fix  kernel <<-- covered here
#|   7.3.0.1    IJ43875m1b.230216.epkg.Z  key_w_fix  kernel
#|   7.3.0.2    IJ43875m2b.230216.epkg.Z  key_w_fix  kernel
#|   7.3.1.1    IJ44594m1a.230216.epkg.Z  key_w_fix  kernel
#
#    Please note that the above table refers to AIX TL/SP level as
#    opposed to fileset level, i.e., 7.2.5.4 is AIX 7200-05-04.
#
#    NOTE:  Multiple iFixes are provided for AIX 7100-05-09 and
#    7200-05-03.
#    IJ43967m9a is for AIX 7100-05-09 with bos.mp64 fileset level 7.1.5.45.
#    IJ43967m9b is for AIX 7100-05-09 with bos.mp64 fileset level 7.1.5.44.
#|   IJ43869m3c is for AIX 7200-05-03 with bos.mp64 fileset level 7.2.5.103.
#|   IJ43869m3d is for AIX 7200-05-03 with bos.mp64 fileset level 7.2.5.101.
#
#    Please reference the Affected Products and Version section above
#    for help with checking installed fileset levels.
#
#    VIOS Level  Interim Fix (*.Z)         KEY        PRODUCT(S)
#    -----------------------------------------------------------
#    3.1.2.21    IJ43995m2b.221027.epkg.Z  key_w_fix  kernel
#    3.1.2.30    IJ43995m2c.221212.epkg.Z  key_w_fix  kernel
#    3.1.2.40    IJ43995m2a.221025.epkg.Z  key_w_fix  kernel
#    3.1.3.10    IJ43869m3b.221212.epkg.Z  key_w_fix  kernel
#    3.1.3.14    IJ43869m3a.221025.epkg.Z  key_w_fix  kernel <<-- covered here
#    3.1.3.21    IJ43869m4a.221017.epkg.Z  key_w_fix  kernel
#    3.1.4.10    IJ43869s5a.221212.epkg.Z  key_w_fix  kernel <<-- covered here
#
#-------------------------------------------------------------------------------
#
class aix_ifix_ij43869 {

    #  Make sure we can get to the ::staging module (deprecated ?)
    include ::staging

    #  This only applies to AIX and VIOS 
    if ($::facts['osfamily'] == 'AIX') {

        #  Set the ifix ID up here to be used later in various names
        $ifixName = 'IJ43869'

        #  Make sure we create/manage the ifix staging directory
        require aix_file_opt_ifixes

        #
        #  For now, we're skipping anything that reads as a VIO server.
        #  We have no matching versions of this ifix / VIOS level installed.
        #
        unless ($::facts['aix_vios']['is_vios']) {

            #
            #  Friggin' IBM...  The ifix ID that we find and capture in the fact has the
            #  suffix allready applied.
            #
            if ($::facts['kernelrelease'] == '7200-05-03-2148') {
                $ifixSuffix = 'm3c'
                $ifixBuildDate = '230216'
            }
            else {
                if ($::facts['kernelrelease'] == '7200-05-04-2220') {
                    $ifixSuffix = 'm4b'
                    $ifixBuildDate = '230216'
                }
                else {
                    if ($::facts['kernelrelease'] == '7200-05-05-2246') {
                        $ifixSuffix = 'm5b'
                        $ifixBuildDate = '230216'
                    }
                    else {
                        $ifixSuffix = 'unknown'
                        $ifixBuildDate = 'unknown'
                    }
                }
            }

        }

        #
        #  This one applies equally to AIX and VIOS in our environment, so deal with VIOS as well.
        #
        else {
            if ($::facts['aix_vios']['version'] == '3.1.3.14') {
                $ifixSuffix = 'm3a'
                $ifixBuildDate = '221025'
            }
            else {
                if ($::facts['aix_vios']['version'] == '3.1.4.10') {
                    $ifixSuffix = 's5a'
                    $ifixBuildDate = '221212'
                }
                else {
                    $ifixSuffix = 'unknown'
                    $ifixBuildDate = 'unknown'
                }
            }
        }

        #================================================================================
        #  Re-factor this code out of the AIX-only branch, since it applies to both.
        #================================================================================

        #  If we set our $ifixSuffix and $ifixBuildDate, we'll continue
        if (($ifixSuffix != 'unknown') and ($ifixBuildDate != 'unknown')) {

            #  Add the name and suffix to make something we can find in the fact
            $ifixFullName = "${ifixName}${ifixSuffix}"

            #  Don't bother with this if it's already showing up installed
            unless ($ifixFullName in $::facts['aix_ifix']['hash'].keys) {
 
                #  Build up the complete name of the ifix staging source and target
                $ifixStagingSource = "puppet:///modules/aix_ifix_ij43869/${ifixName}${ifixSuffix}.${ifixBuildDate}.epkg.Z"
                $ifixStagingTarget = "/opt/ifixes/${ifixName}${ifixSuffix}.${ifixBuildDate}.epkg.Z"

                #  Stage it
                staging::file { "$ifixStagingSource" :
                    source  => "$ifixStagingSource",
                    target  => "$ifixStagingTarget",
                    before  => Exec["emgr-install-${ifixName}"],
                }

                #  GAG!  Use an exec resource to install it, since we have no other option yet
                exec { "emgr-install-${ifixName}":
                    path     => '/bin:/sbin:/usr/bin:/usr/sbin:/etc',
                    command  => "/usr/sbin/emgr -e $ifixStagingTarget",
                    unless   => "/usr/sbin/emgr -l -L $ifixFullName",
                }

                #  Explicitly define the dependency relationships between our resources
                File['/opt/ifixes']->Staging::File["$ifixStagingSource"]->Exec["emgr-install-${ifixName}"]

            }

        }

    }

}
